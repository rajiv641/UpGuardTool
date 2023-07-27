#!/bin/env python3
import argparse
import getpass
import io
import json
import logging
import os
import re
import string
import sys
from pprint import pformat, pprint

import arrow
import requests
import termcolor
from librack2.auth import Auth, CoreAuth
from librack2.core.account import CoreAccount
from librack2.core.server import CoreServer
from librack2.core.ticket import CoreTicket, CoreTicketPriority, valid_categories
from librack2.exceptions import LibrackError
from librack2.password_safe import PasswordSafeProject
from librack2.server import get_servers
from tabulate import tabulate

# External System Constants
CONFIGURATION_MONITORING_SKU = 109508
PASSWORDSAFE_PROJECT_ID = 18316

# Node Fields that can be updated, more or less
allowed_updates = [
    "connection_manager_group_id",
    "description",
    "environment_id",
    "external_id",
    "ip_address",
    "mac_address",
    "medium_group",
    "medium_hostname",
    "medium_password",
    "medium_port",
    "medium_type",
    "medium_username",
    "name",
    "node_type",
    "online",
    "operating_system_family_id",
    "operating_system_id",
    "primary_node_group_id",
    "short_description",
]


class Upguard:
    __url = ""
    __file = None

    def __init__(self, api_key, secret_key, base_url, **_):
        self.__params = {}
        self.setup(api_key, secret_key, base_url)

    def setup(self, api_key, secret_key, base_url):
        self.__params["upguard_api_key"] = api_key
        self.__params["upguard_secret_key"] = secret_key
        self.__params["base_url"] = base_url

    def __call(self, url="", method="GET", data=None, debug=0):
        url = self.__params["base_url"] + url
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": 'Token token="%s%s"'
            % (self.__params["upguard_api_key"], self.__params["upguard_secret_key"]),
        }

        if debug:
            print("CALLING method %s %s with\nHEADERS: " % (method, url), headers)
            print("DATA: ")
            print(data)

        if data is not None:
            data = json.dumps(data)

        kwargs = {"data": data, "headers": headers}
        if method == "GET":
            response = requests.get(url, **kwargs)

        if method == "POST":
            response = requests.post(url, **kwargs)

        if method == "PUT":
            response = requests.put(url, **kwargs)

        if method == "DELETE":
            response = requests.delete(url, **kwargs)

        httpCode = response.status_code
        if debug:
            print("RESPONSE: ", httpCode)
        if (httpCode >= 200) and (httpCode < 300):
            if httpCode == 204:  # OK but no response body
                j = {}
            else:
                j = json.loads(response.text)
                if debug:
                    print("OUTPUT: ", j)
            return [httpCode, j]
        else:
            if debug:
                print(
                    "REQUEST failed, code ",
                    httpCode,
                    " body: ",
                    json.loads(response.text),
                )
            return None

    def showNode(self, id, debug=0):
        url = "/api/v1/nodes/%s.json" % (id)
        out = self.__call(url=url, debug=debug)
        if not out:
            return None
        else:
            return out[1]

    def searchByIDS(self, ids, debug=0):
        # call the function above on all IDs
        nodes = []
        for id in ids:
            nd = self.showNode(id, debug)
            if nd is not None:
                nodes.append(nd)
        return nodes

    def searchByCoreID(self, id, debug=0):
        url = "/api/v1/nodes/lookup.json?external_id=%s" % (id)
        out = self.__call(url=url, debug=debug)
        if not out:
            return None

        id = out[1]["node_id"]
        return self.showNode(id)

    def searchByCoreIDS(self, ids, debug=0):
        # call the function above on all IDs
        nodes = []
        for id in ids:
            nd = self.searchByCoreID(id, debug)
            if nd is not None:
                nodes.append(nd)
        return nodes

    # doesn't work. Odef ubset self, debug==of search parameters are supported
    def searchByOSID(self, id, debug=0):
        url = "/api/v1/nodes/lookup.json?operating_system_family_id=%s" % (id)
        out = self.__call(url=url, debug=debug)
        if not out:
            return None

        id = out[1]["node_id"]
        return self.showNode(id)

    def index(self, debug=0):
        url = "/api/v2/nodes.json?page=1&per_page=10000"
        out = self.__call(url=url, debug=debug)
        if not out:
            return None

        return out[1]

    def SearchByOS(self, id, debug=0):
        idx = self.index()
        if not isinstance(idx, list):
            return None

        devices = []
        for x in idx:
            if debug:
                print("cmp %s and %s\n", x["operating_system_family_id"], id)
            if x["operating_system_family_id"] == id:
                devices.append(x)

        return devices

    def SearchByLinux(self, debug=0):
        return self.SearchByOS(2, debug)

    def SearchByWindows(self, debug=0):
        return self.SearchByOS(1, debug)

    def filterByLinux(self, nodes, debug=0):
        out = []
        for n in nodes:
            if n["operating_system_family_id"] == 2:
                out.append(n)
        # out = [n for n in nodes if n['operating_system_family_id']==2]
        # print("filterByLinux returning: " + pformat(out))
        return out

    def filterByWindows(self, nodes, debug=0):
        out = []
        for n in nodes:
            if n["operating_system_family_id"] == 1:
                out.append(n)
        # out = [n for n in nodes if n['operating_system_family_id']==1]
        # print("filterByWindows returning: " + pformat(out))
        return out

    def getChanges(self, id, frm, to, debug=0):
        url = "/api/v2/change_report.json?node_id=%s&date_from=%s&date_to=%s" % (
            id,
            frm,
            to,
        )
        if debug:
            print("url: %s\n" % (url))
        out = self.__call(url, "GET", debug=debug)
        if not out:
            return None

        return out[1]

    def updateNode(self, id, data, debug=0):
        url = "/api/v2/nodes/%s.json" % (id)
        out = self.__call(url=url, method="PUT", data=data, debug=debug)
        if isinstance(out, list) and (out[0] == 204):
            return True
        return False

    def update_devices(self, elems, newvals, debug=0):
        # newvals is an hash of key: NEWvalue
        if not isinstance(elems, list):
            print(__name__, " input argument is not an array\n")
        if "id" in newvals:
            print("ID can't be updated!, exiting")
            return False

        for k in newvals.keys():
            if not k in allowed_updates:
                print("Key %s can't be modified, exiting." % k)
                return False

        for m in elems:
            obj = self.showNode(m["id"])
            if not obj:
                print(
                    "Couldn't get properties of %s (%s). Skipping\n"
                    % (m["name"], m["id"])
                )
                continue

            data = {"node": {}}
            data["node"].update(newvals)
            print("UPDATING node %s (%s) to %s" % (m["name"], m["id"], pformat(data)))
            if True:
                out = self.updateNode(m["id"], data, debug)
                if debug:
                    pprint(out)
                if out != True:
                    print("UPDATE FAILED on %s (%d)\n" % (m["name"], m["id"]))
                    print(out)
                    continue
            if debug:
                nd = self.showNode(m["id"], debug * 0)
                newstr = "After successful update, Node %s id %s " % (
                    nd["name"],
                    nd["id"],
                )
                strs = []
                for k in newvals.keys():
                    strs.append("k: %s, v: %s" % (k, nd[k]))
                print(newstr + "\n\t" + str.join("\n\t", strs) + "\n")
        return True

    def addNode(self, nd, extra, debug=0):
        url = "/api/v2/nodes.json"
        if debug:
            print("url: %s\n" % (url))
        # Node types
        # CODE  TYPE
        # SV  Server
        # DT  Desktop
        # SW  Network Switch
        # FW  Firewall
        # RT  Router
        # PH  Smart Phone
        # RB  Robot
        # SS  SAN Storage
        # WS  Website
        #

        # Medium types
        # 1 AGENT
        # 3 SSH
        # 6 HTTPS
        # 7 WINRM
        # 8 SERVICE
        # 9 WEB

        kmap = {
            "username": "medium_username",
            "password": "medium_password",
            "hostname": "medium_hostname",
            "port": "medium_port",
        }

        d = {
            "name": nd["name"],
            "node_type": "SV",  # forcing server
            "medium_type": nd["medium_type"],  # mostly ssh
            "medium_username": nd["username"],  # mostly ssh
            "medium_hostname": nd["hostname"],
            "external_id": nd["external_id"],
        }
        if "password" in nd:
            d["medium_password"] = nd["password"]
        if "port" in nd:
            d["medium_port"] = nd["port"]
        if "connection_manager_group_id" in nd:
            d["connection_manager_group_id"] = nd["connection_manager_group_id"]

        for k in extra.keys():
            if k in kmap:
                tmp = extra[k]
                extra[kmap[k]] = extra[k]
                del extra[k]

        for k in extra.keys():
            if not k in allowed_updates:
                print("Key %s can't be used when adding nodes, exiting." % k)
                return False
            else:
                d[k] = extra[k]

        out = self.__call(url, "POST", data=d, debug=debug)
        if not out:
            return None
        if out[0] != 201:
            if debug:
                print("Adding node failed")
            return None

        return out[1]

    def add_core_nodes(self, nodes, extra, debug=0):
        # first get the list of connection managers
        ok = True
        cms = self.getCMGS(debug=debug)
        if debug:
            print("Connection managers:")
            pprint(cms)

        for n in nodes:
            if self.searchNode(n["number"], debug):
                print(
                    "The device %s is already present in Upguard. Skipping."
                    % (n["number"])
                )
                continue
            if n["is_linux"]:
                cm = self.getLinuxCM(cms, n["datacenter.symbol"])
            elif n["is_windows"]:
                cm = self.getWindowsCM(cms, n["datacenter.symbol"])
            if not n["primary_nat_ip"]:
                print(
                    "Couldn't find an IP for device %s in %s, OS %s, IP: %s. Skipping."
                    % (
                        n["number"],
                        n["datacenter.symbol"],
                        n["os"],
                        n["primary_nat_ip"],
                    )
                )
                continue
            if cm is None:
                print(
                    "Couldn't find an appropriate connection manager for device %s in %s, OS %s. Skipping."
                    % (n["number"], n["datacenter.symbol"], n["os"])
                )
                continue
            d = {
                "name": n["name"],
                "connection_manager_group_id": cm,
                "external_id": n["number"],
                "hostname": n["primary_nat_ip"],
            }
            if "username" in extra and extra["username"]:
                d["username"] = extra["username"]
            elif n["is_windows"]:
                d["username"] = "winguard"
            else:
                d["username"] = "upguard"

            if n["is_windows"]:
                d["port"] = 5986
                d["medium_type"] = 7
            else:
                d["port"] = 22
                d["medium_type"] = 3

            if not self.addNode(d, extra, debug):
                print(
                    "Adding device %s type %d DC %s OS %s failed"
                    % (
                        n["number"],
                        n["datacenter.symbol"],
                        n["os"],
                        n["primary_nat_ip"],
                    )
                )
                ok = False
            else:
                print("Added node %s" % n["name"])

        return ok

    def delNode(self, id, debug=0):
        url = "/api/v2/nodes/%s.json" % (id)
        out = self.__call(url=url, method="DELETE", debug=debug)
        if isinstance(out, list) and (out[0] == 204):
            return True
        return False

    def delete_devices(self, nodes, debug=0):
        ok = True
        for n in nodes:
            print("delete node %s" % n["id"])
            if not self.delNode(n["id"], debug):
                print("Removal of device %s failed, skipping" % n)
                ok = False
        return ok

    def delete_core_devices(self, nodes, debug=0):
        ids = [n["number"] for n in nodes]
        ugnodeds = self.searchByCoreIDS(ids, debug)
        for n in ugnodeds:
            self.delNode(n["id"], debug)

    def update_core_devices(self, nodes, data, debug=0):
        ids = [n["number"] for n in nodes]
        ugnodes = self.searchByCoreIDS(ids, debug)
        if not len(ugnodes):
            print("No nodes found to update, skipping")
            return False
        return self.update_devices(ugnodes, data, debug)

    def searchNode(self, id, debug=0):
        url = "/api/v2/nodes/lookup.json?external_id=%s" % (id)
        out = self.__call(url=url, method="GET", debug=debug)
        if not out:
            return None

        return out[1]["node_id"]

    def getNodeGroups(self, debug=0):
        url = "/api/v2/node_groups.json?page=1&per_page=1000"
        out = self.__call(url=url, method="GET", debug=debug)
        if not out:
            return None

        return out[1]

    def showNodeGroups(self, debug=0):
        ngs = self.getNodeGroups(debug)
        for n in ngs:
            print("ID: %s, GROUP: %s" % (n["id"], n["name"]))

    def nodeGroupRemoveNode(self, gid, nodeid, debug=0):
        gid = int(gid)
        nodeid = int(nodeid)
        if not (gid > 0 and nodeid > 0):
            print("At least one of the group and nodeid is wrong, exit")
            return False
        url = "/api/v2/node_groups/%d/remove_node.json?node_id=%d" % (gid, nodeid)
        out = self.__call(url=url, method="POST", debug=debug)
        if isinstance(out, list) and (out[0] == 204):
            return True
        return False

    def getNodeNodeGroups(self, nid, debug=0):
        url = "/api/v2/nodes/%s/node_groups.json" % nid
        out = self.__call(url=url, method="GET", debug=debug)
        if not out:
            return None

        return out[1]

    def nodeGroupRemoveNodes(self, nodes, debug=0):
        for n in nodes:
            groups = self.getNodeNodeGroups(n["id"], debug)
            for g in groups:
                logging.warning(
                    "Removing node %s from Node Group: %s %s"
                    % (n["id"], g["id"], g["name"])
                )
                if g["name"].upper() == "SUSPENDED":
                    pass
                self.nodeGroupRemoveNode(g["id"], n["id"], debug)

        return True

    def getEnvironments(self, debug=0):
        url = "/api/v2/environments.json?page=1&per_page=1000"
        out = self.__call(url=url, method="GET", debug=debug)
        if not out:
            return None

        return out[1]

    def showEnvironments(self, debug=0):
        envs = self.getEnvironments(debug)
        for e in envs:
            print("Environment ID: %s, name: %s" % (e["id"], e["name"]))

    def createSuspendedEnv(self, debug=0):
        url = "/api/v2/environments"
        d = {
            "name": "SUSPENDED",
            "short_description": "Environment for SUSPENDED nodes",
        }
        out = self.__call(url=url, method="POST", data=d, debug=debug)
        if isinstance(out, list) and (out[0] == 201):
            return out[1]
        return False

    def moveNodesToSuspended(self, nodes, debug=0):
        eid = None
        envs = self.getEnvironments(debug)
        for e in envs:
            if e["name"] == "SUSPENDED":
                eid = e["id"]
                break
        if not eid:
            print("Couldn't find SUSPENDED Environment, trying to create")
            newenv = self.createSuspendedEnv(debug)
            if not isinstance(newenv, dict) or not "id" in newenv:
                print("Couldn't create the SUSPENDED environment, exiting")
                return False
            eid = newenv["id"]
        data = {"environment_id": eid}
        return self.update_devices(nodes, data, debug)

    def getCMS(self, debug=0):  # returns the list of connection managers
        url = "/api/v2/connection_managers.json"
        out = self.__call(url=url, method="GET", debug=debug)
        if not out:
            return None

        return out[1]

    def getusers(self, debug=0):  # returns the list of Users
        url = "/api/v2/users.json?invited=true"
        out = self.__call(url=url, method="GET", debug=debug)
        if not out:
            return None

        return out[1]

    def getLinuxCM(self, cms, dc):  # returns the list of connection managers
        str1 = dc + "_SSH"
        for c in cms:
            if str1.upper() in c["name"].upper():
                return c["id"]
        return None

    def getWindowsCM(self, cms, dc):  # returns the list of connection managers
        str1 = dc + "_WinRM"
        for c in cms:
            if c["name"].upper() == str1.upper():
                return c["id"]
        return None

    def getCMGS(self, debug=0):  # returns the list of connection manager groups
        url = "/api/v2/connection_manager_groups.json"
        out = self.__call(url=url, method="GET", debug=debug)
        if not out:
            return None

        return out[1]

    def scanNode(self, id, debug=0):
        # url = "/api/v2/jobs.json?type=11&type_id=%s" % (id)
        url = "/api/v2/nodes/%s/start_scan.json" % (id)
        out = self.__call(url=url, method="POST", debug=debug)
        if isinstance(out, list) and (out[0] >= 200) and (out[0] < 300):
            j = out[1]
            if "delayed_job" in j and j["job_id"]:
                return j["job_id"]
        return False

    def getLastScan(self, id, debug=0):
        # url = "/api/v2/jobs.json?type=11&type_id=%s" % (id)
        url = "/api/v2/nodes/%s/last_scan_status.json" % (id)
        out = self.__call(url=url, method="GET", debug=debug)
        if isinstance(out, list) and (out[0] == 200):
            j = out[1]
            return j
        return False

    def showCMS(self, debug=0):
        cms = self.getCMS(debug=debug)
        print("Found Connection Managers... (hostname, type, version, last contact)")
        for x in cms:
            tm = x["last_contact"]
            tm = tm.replace("T", " ")
            tm = re.sub("\.[0-9]+", "", tm)
            tm = re.sub("(\-[0-9]{2}):[0-9]{2}$", " \\1", tm)
            print(
                "%s, %s, %s, %s"
                % (x["hostname"], x["agent_type"], x["agent_version"], tm)
            )

    def showUsers(self, debug=0):  # List the detail of the Active users
        cms = self.getusers(debug=debug)
        print("Found User Details... (ID, Name, Surname, Email, Role, Last Sign in at)")
        # print (cms)
        for x in cms:
            tm = x["last_sign_in_at"]
            tm = tm.replace("T", " ")
            tm = re.sub("\.[0-9]+", "", tm)
            tm = re.sub("(\-[0-9]{2}):[0-9]{2}$", " \\1", tm)
            print(
                "%s, %s, %s, %s, %s, %s"
                % (x["id"], x["name"], x["surname"], x["email"], x["role"], tm)
            )

    def showCMGS(self, debug=0):
        cmgs = self.getCMGS(debug=debug)
        for x in cmgs:
            print("Found Connection Manager Groups: " + x["name"])

    def getEvents(self, cmid, debug=0):
        mago = arrow.utcnow().shift(months=-10)  # 1 month ago
        url = (
            "/api/v2/events.json?per_page=10000&page=1&query=type=Connection Manager Offline AND variables.connection_manager_id=%d"
            % (int(cmid))
        )  # &date_from=" + str(mago)
        # the filter on starts/times doesn't seem to work
        # url="/api/v2/events.json?per_page=10000&page=1&query=type=Connection Manager Offline AND variables.connection_manager_id=%d AND created_at>%s" % (int(cmid), mago)
        out = self.__call(url=url, method="GET", debug=debug)
        if isinstance(out, list) and (out[0] == 200):
            j = out[1]
            return j
        return False

    def getTypes(self, debug=0):
        url = "/api/v2/events/types.json"
        out = self.__call(url=url, method="GET", debug=debug)
        if isinstance(out, list) and (out[0] == 200):
            j = out[1]
            return j
        return False

    # Connection Manager Offline, and type=Connection Manager Group Offline
    def checkCMS(self, debug):
        cms = self.getCMS(debug)
        now = arrow.utcnow().to("GMT").timestamp
        types = self.getTypes(debug)
        # pprint(types)
        CMtypes = []
        for t in types:
            if t["name"] in [
                "Connection Manager Group Offline",
                "Connection Manager Offline",
            ]:
                CMtypes.append(t["id"])
        if debug:
            pprint(CMtypes)

        for c in cms:
            dt = c["last_contact"]
            gmtime = arrow.get(c["last_contact"]).to("GMT")
            last = gmtime.timestamp
            events = self.getEvents(c["id"], debug)
            # pprint(events)
            cmdown = None
            for e in events:
                eventtm = arrow.get(e["created_at"]).to("GMT")
                ets = eventtm.timestamp
                if now - ets > 2 * 3600:
                    continue
                if now - ets > 1800:
                    cmdown = eventtm

            if now - last > 2 * 3600:
                cmdown = gmtime

            if cmdown:
                print(
                    "The CM %s seems to be down: %s"
                    % (c["hostname"], cmdown.humanize())
                )
            # Zakk: type=Connection Manager Offline, and type=Connection Manager Group Offline
            # last_contact must be recent
        return True

    def fixNatFqdn(self, core, args, nodes, debug):
        ids = [n["external_id"] for n in nodes]
        if ids:
            servers = core.searchComputers(ids, debug=0)
            if not servers:
                print("No servers found, skipping update")
            else:
                for n in nodes:
                    for s in servers:
                        if str(s["number"]) == str(n["external_id"]):
                            # simulate an update with a preformatted data in json format
                            if args.replaceNameWithFQDN:
                                dt = {"medium_hostname": n["name"]}
                            elif args.replaceNameWithNatIP:
                                dt = {"medium_hostname": s["primary_nat_ip"]}
                            n["number"] = n["external_id"]
                            self.update_core_devices([n], dt, debug)
        return False


class Core:
    def login(self, username="", rackertoken=None, debug=False):
        "Tries to authenticate with CORE with the given or current username and returns the connection handle"
        if not username:
            username = os.getenv("USER")
        if not username:
            username = input("Username: ")
        if not rackertoken:
            rackertoken = os.getenv("RACKERTOKEN")
        if not rackertoken:
            # Get credentials from hammertime if already authenticated with it.
            ht_cmd = os.popen("ht --batch credentials 2>/dev/null")
            rackertoken = ht_cmd.read().strip()
            ht_rc = ht_cmd.close()
        try:
            if not rackertoken:
                connector = Auth("Upguard Tools", interactive=True, sso=username)
            else:
                connector = Auth("Rackertoken authentication", rackertoken=rackertoken)
            rackertoken = connector.rackertoken
            # If we didn't originally get the rackertoken from hammertime, then we might as well use it to auth with ht
            if ht_rc == 256:
                ht_cmd = os.popen(
                    f"ht --batch --rackertoken={rackertoken} credentials 2>/dev/null"
                )
                ht_rc == ht_cmd.close()
        except Exception as e:
            print("Couldn't authenticate username %s" % username)
            print(e)
            return None
        self.connector = connector
        return connector

    def __init__(self):
        pass

    def searchTicketComputers(self, connector, ticketid, debug=0):
        try:
            ticket = CoreTicket(connector, ticketid)
        except LibrackError as ex:
            print(ex.message)
            sys.exit(ex.code)

        res = ticket.server_ids
        if not res:
            return None
        if debug:
            print("results: ")
            pprint(res)

        return res

    def searchComputers(self, server_ids, check_sku=False, debug=0):
        devicedetails = []
        ug_sku = CONFIGURATION_MONITORING_SKU if check_sku else None
        if server_ids:
            for server_id in server_ids:
                try:
                    core_server = CoreServer(self.connector, server_id)
                    if check_sku:
                        has_sku = bool(core_server.parts_by_sku_id(ug_sku))
                    else:
                        has_sku = None
                    devicedetails += [
                        (
                            server_id,
                            core_server.is_cluster,
                            core_server.hypervisor,
                            core_server.os_type,
                            core_server.os_version,
                            core_server.status,
                            core_server.primary_ip,
                            core_server.datacenter,
                            has_sku,
                        )
                    ]
                except LibrackError as ex:
                    print(ex.message)
                    sys.exit(ex.code)
            # Print a table title:
            os.system("clear")
            print(termcolor.colored("Devices Linked to the Ticket", "green"))
            print(
                tabulate(
                    devicedetails,
                    headers=[
                        "Server Number",
                        "Is_Cluster",
                        "Hypervisor",
                        "OS Type",
                        "OS Version",
                        "Status",
                        "Primary IP",
                        "DataCenter",
                        "Has Configuration Monitoring SKU",
                    ],
                )
            )
        else:
            print("No Server attached to the Ticket ")

    def filter(self, nodes, args, debug=0):
        out = []

        comps = self.searchComputers(nodes, debug=debug)
        if debug:
            pprint(comps)
        ## TODO - this function currently does nothing. Use the original code below to see what is needed or remove function
        # for c in comps:
        #  if(args.linuxOnly and c['is_linux']):
        #    out.append(c)
        #  elif(args.windowsOnly and c['is_windows']):
        #    out.append(c)
        #  elif(not args.linuxOnly and not args.windowsOnly and (c['is_linux'] or c['is_windows'])):
        #    out.append(c)

        return out

    def searchAccountComputers(self, account_num, check_sku=False, debug=0):
        ug_sku = CONFIGURATION_MONITORING_SKU if check_sku else None
        try:
            core_obj = CoreAccount(self.connector, str(account_num))
        except LibrackError as ex:
            print(ex.message)
            sys.exit(ex.code)

        results = []
        import time

        if core_obj:
            server_list = core_obj.server_ids
            core_server_list = get_servers(self.connector, server_list)
            for item in core_server_list:
                is_linux = False
                is_windows = False

                if item.os_type == "linux":
                    is_linux = True
                elif item.os_type == "windows":
                    is_windows = True
                part = None
                if check_sku:
                    part = item.parts_by_sku_id(ug_sku)
                    has_ug_sku = bool(part)
                else:
                    has_ug_sku = None
                case = {
                    "name": item.name,
                    "number": item.id,
                    "status": item.status,
                    "is_linux": is_linux,
                    "is_windows": is_windows,
                    "has_ug_sku": has_ug_sku,
                }
                results.append(case)
        else:
            print("No servers in the Core account %s" % account_num)
            return results

        return results

    def passwordsafe(self, project_id, account):  ## Password Safe Project ###
        all_creds = PasswordSafeProject(self.connector, project_id=project_id)
        found_cred = [
            cred
            for cred in all_creds.credentials
            if cred.category == "api_keys" and cred.hostname == str(account)
        ]
        mydict = {}

        if found_cred:
            mydict = found_cred[0].dump()
            return mydict
        else:
            logging.warning(f"Account Number: {account} Not found in passwordsafe")
            return None

    def __call_core__(self, mycall, debug=0):
        # results = self.__connector__.query(mycall)
        results = ""
        if debug:
            print(__name__, " CALL: ", mycall, "\nRESULT: ", results)
        if not results:
            if debug:
                print(__name__, "No results returned from query(), exiting\n")
            return None
        if "success" in results[0] and (not results[0]["success"]):
            if debug:
                print(__name__, "Operation failed, exiting")
            return None

        return results[0]


def parse_cli():
    # fmt: off
    parser = argparse.ArgumentParser(description="Upguard Tools: A command line tool to audit/add/update/delete servers and devices in Upguard")


    actions_group = parser.add_mutually_exclusive_group()
    actions_group.add_argument("--add", "-a", action="store_true", dest="adds", default=False, help="Add nodes")
    actions_group.add_argument("--update", "-u", action="store_true", dest="updates", default=False, help="Update nodes")
    actions_group.add_argument("--delete", "-D", action="store_true", dest="deletes", default=False, help="Delete nodes")
    actions_group.add_argument("--scan", action="store_true", dest="scanNode", default=False, help="Scan the specified nodes")
    actions_group.add_argument("--audit", action="store_true", dest="audit", default=False, help="Perform an audit on a given account showing the status of the devices (present/absent)")
    actions_group.add_argument("--nat", action="store_true", dest="replaceNameWithNatIP", default=False, help="for each Upguard entry in the ticket replace the host name with the primary_nat_ip defined in CORE")
    actions_group.add_argument("--fqdn", action="store_true", dest="replaceNameWithFQDN", default=False, help="for each Upguard entry in the ticket replace the host name with the FQDN defined in CORE")
    actions_group.add_argument("--check-cms", action="store_true", dest="checkCMS", default=False, help="Show the status of connection managers")
    actions_group.add_argument("--susp", action="store_true", dest="moveNodesToSuspended", default=False, help="Move nodes from the current environment to SUSPENDED (prevents scanning preserving the node groups)")
    actions_group.add_argument("--show", "-s", action="store_true", dest="showNodes", default=False, help="Show the values of nodes before and after eventual updates")

    id_group = parser.add_mutually_exclusive_group()
    id_group.add_argument("--ids", "-i", metavar="N", type=int, dest="IDS", nargs="+", help="Node IDs to work on")
    id_group.add_argument("--coreids", "-c", metavar="N", type=int, dest="CoreIDS", nargs="+", help="CORE ID nodes to work on")

    parser.add_argument("--os-filter", type=str, choices=["windows", "linux", "all"], default="all", required=False, help="Select 'windows', 'linux', or 'all' devices")
    parser.add_argument("--fields", dest="showFields", type=str, nargs="+", default=["id", "name"], help="Show these values during a node list")
    parser.add_argument("--data", type=json.loads, dest="data", help="Json data to Update nodes")
    parser.add_argument("--ticket", "-t", type=str, dest="ticket", help="Specify CORE ticket to use to identify the devices")
    parser.add_argument("--show-cms", "-C", action="store_true", dest="showConnectionManagers", default=False, help="Show the list of connection managers")
    parser.add_argument("--show-user", "-H", action="store_true", dest="showUsers", default=False, help="Show the list of Users")
    parser.add_argument("--show-cmgs", "-G", action="store_true", dest="showConnectionManagerGroups", default=False, help="Show the list of connection manager groups")
    parser.add_argument("--show-ngs", action="store_true", dest="showNodeGroups", default=False, help="Show the list of node groups")
    parser.add_argument("--ngr", action="store_true", dest="nodeGroupRemoveNodes", default=False, help="Remove nodes from the node groups")
    parser.add_argument("--show-envs", action="store_true", dest="showEnvironments", default=False, help="Show the list of environments")
    parser.add_argument("--show-credentials", action="store_true", help="Show the upguard credentials from passwordsafe")
    parser.add_argument("--rackertoken", type=str, dest="rackertoken", default=None, help="Rackertoken to use for auth")

    parser.add_argument("--account", "-A", metavar="N", type=int, dest="account", required=True, help="Account ID to select in CORE")
    parser.add_argument("--debug", "-d", action="store_true", dest="debug", default=False, help="turn on debug mode")
    parser.add_argument("--loglevel", "-l", type=str.upper, choices=list(logging._levelToName.values()), help="Set the log level")

    audit_group = parser.add_argument_group("audit options")
    audit_group.add_argument("--mismatch-filter", "-M", type=str, choices=["missing", "present", "all"], default="all", help="During an audit show 'all' nodes or just those which are 'missing' or 'present' in upguard")
    audit_group.add_argument("--fix-external-ids","--fix", action="store_true", default=False, help="During audits fix the lack of external id by trying to guess it from the node name")
    audit_group.add_argument("--output-format", dest='output_format', choices=["csv","table","default"], default="default", help="What format to output results in")
    audit_group.add_argument("--check-sku", "-K", action="store_true", dest="check_sku", default=False, help="Check whether each active device has the Configuration Monitoring SKU")

    # fmt: on

    command_args = parser.parse_args()

    if command_args.CoreIDS:
        for c in command_args.CoreIDS:
            if c < 100000 or c > 2000000:
                logging.fatal("At least one of the specified CORE ids seems to be invalid, exit.")
                print(
                    "At least one of the specified CORE ids seems to be invalid, exit."
                )
                exit(1)

    if command_args.IDS:
        for c in command_args.IDS:
            if c < 0:
                print(
                    "At least one of the specified UPGUARD ids seems to be invalid, exit."
                )
                exit(1)

    ok = True
    if isinstance(command_args.updates, list) and len(command_args.updates):
        for k in command_args.updates.keys():
            if k not in allowed_updates:
                print("Field %s can't be updated" % (k))
                ok = False
    if not ok:
        exit(1)

    return command_args


def get_ug_credentials(core: Core, account: int):
    project_id = PASSWORDSAFE_PROJECT_ID
    try: 
        pws_creds = core.passwordsafe(project_id=project_id, account=account)
        credentials = {
            "account": pws_creds["hostname"],
            "description": pws_creds["description"],
            "api_key": pws_creds["username"],
            "secret_key": pws_creds["password"],
            "base_url": pws_creds["url"],
        }
        return credentials
    except:
        logging.fatal(f"Couldn't get credentials for account {account}")
        exit(1)


def add_nodes(ug, core, args):
    if not isinstance(args.CoreIDS, list):
        print("Missing CORE IDS to add, exiting")
        exit(1)
    if isinstance(args.data, dict):
        dt = args.data
    else:
        dt = {}

    nodes = core.filter(args.CoreIDS, args, args.debug)
    if len(nodes):
        if args.debug:
            pprint(nodes)
    else:
        print("No nodes suitable for adding, exiting")
        return None
    return ug.add_core_nodes(nodes, dt, args.debug)


def show_nodes(ug, nodes, args):
    print("found: %s elems" % len(nodes))
    for x in nodes:
        nd = ug.showNode(x["id"])
        if len(args.showFields):
            flds = ["%s: %s" % (f, nd[f]) for f in args.showFields]
            print(", ".join(flds))
        else:
            print("Node: %s ID: %s" % (nd["name"], nd["id"]))

        if args.debug:
            pprint(nd)


def show_audit(
    core: Core,
    ug: Upguard,
    account_num,
    mismatch_filter="all",
    fix_external_ids=False,
    output_format="default",
    check_sku=False,
    os_filter="all",
    debug=False,
):
    core_account_computers = core.searchAccountComputers(
        account_num, debug=debug, check_sku=check_sku
    )
    if debug:
        print("get nodes from upguard")
    nodes = ug.index()
    if debug:
        pprint(nodes)
    logging.debug(f"Nodes: {nodes}")
    umap = {str(x["external_id"]): x["id"] for x in nodes if x["external_id"]}
    present = []
    not_present = []

    n = 0
    if output_format == "csv":
        print(
            '"CoreID", "Device type", "Core device name", "Upguard node ID", "Core status", "Last scan status", "Last scan message", "Last scan date", "Has problems", "Has Configuration Monitoring SKU"'
        )
    for computer in core_account_computers:
        n += 1
        ls1 = ""
        ls2 = ""
        computer_number = str(computer["number"])
        if output_format == "csv":
            computer_status = computer["status"]
        elif computer["status"] == "Online/Complete":
            computer_status = termcolor.colored(computer["status"], "green")
        else:
            computer_status = termcolor.colored(computer["status"], "red")
        if computer["is_linux"]:
            if os_filter == "windows":
                continue
            label = "L"
        elif computer["is_windows"]:
            if os_filter == "linux":
                continue
            label = "W"
        else:
            label = "-"
        givealook = ""
        glstr = ""
        if (
            mismatch_filter in ["present", "all"]
            and computer_number in umap
            and umap[computer_number]
        ):
            lastscan = ug.getLastScan(umap[computer_number], debug=0)
            scandate = lastscan["updated_at"]
            parts = scandate.split("T")
            parts[1] = parts[1][0:5]
            scandate = "%s %s" % (parts[0], parts[1])
            laststat = lastscan["status_string"].strip()
            scanstatus = laststat
            if laststat == "success":
                if output_format == "csv":
                    ls1 = laststat
                else:
                    ls1 = termcolor.colored(laststat, "green")
                ls2 = ""
                laststat = ls1
            elif "report" in lastscan and lastscan["report"]:
                x = json.loads(lastscan["report"])
                try:
                    if output_format == "csv":
                        ls1 = laststat
                        ls2 = x[0]["generate_node_scan"]["messages"][0].strip()
                    else:
                        ls1 = termcolor.colored(laststat, "red")
                        ls2 = termcolor.colored(
                            x[0]["generate_node_scan"]["messages"][0].strip(), "magenta"
                        )

                    laststat = ls1 + " " + ls2
                except Exception:
                    try:
                        x = x[0]
                        ks = x.keys()[0].strip()
                        if output_format == "csv":
                            ls1 = laststat
                            ls2 = ks
                        else:
                            ls1 = termcolor.colored(laststat, "red")
                            ls2 = termcolor.colored(ks, "magenta")
                        laststat = ls1 + " " + ls2
                    except Exception:
                        ls1 = ""
                        ls2 = ""
                        laststat = ""
            else:
                if output_format == "csv":
                    laststat = laststat
                else:
                    laststat = termcolor.colored(laststat, "cyan")
            if (scanstatus != "success") and (computer["status"] == "Online/Complete"):
                givealook = "*"
                if output_format == "csv":
                    glstr = "To check"
                else:
                    glstr = termcolor.colored("To check", "red")
            sku_status = computer["has_ug_sku"]
            sku_status_map = {True: "Present", False: "Missing", None: "Unknown"}
            sku_status_string = termcolor.colored(sku_status_map[sku_status], "red")
            if sku_status:
                sku_status_string = termcolor.colored(
                    sku_status_map[sku_status], "green"
                )
            elif sku_status is None:
                sku_status_string = termcolor.colored(
                    sku_status_map[sku_status], "yellow"
                )

            if output_format == "csv":
                present.append(
                    '"%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"'
                    % (
                        computer["number"],
                        label,
                        computer["name"],
                        umap[computer_number],
                        computer_status,
                        ls1,
                        ls2,
                        scandate,
                        givealook,
                        sku_status,
                    )
                )
            else:
                present.append(
                    "%s[%s] with name %s has node id %s. Status: %s. SKU Status: %s. Last scan: %s at %s. %s"
                    % (
                        computer["number"],
                        label,
                        computer["name"],
                        umap[computer_number],
                        computer_status,
                        sku_status_string,
                        laststat,
                        scandate,
                        glstr,
                    )
                )
            # pprint(lastscan)
        elif mismatch_filter in ["missing", "all"]:
            if output_format == "csv":
                not_present.append(
                    '"%s", "%s", "%s", "%s"'
                    % (computer["number"], label, computer["name"], computer_status)
                )
            else:
                not_present.append(
                    "%s[%s] with name %s. Status %s"
                    % (computer["number"], label, computer["name"], computer_status)
                )

    str1 = "Devices defined in Upguard: %d\n" % (len(present))
    print(str1 + "\n".join(present))
    print
    str1 = "Devices NOT defined in Upguard: %d\n" % (len(not_present))
    print(str1 + "\n".join(not_present))

    print
    for n in nodes:
        exid = None
        exidstr = ""
        if not n["external_id"]:
            matchObj = re.search(r"^[a]?([0-9]{5,})-", n["name"], re.M)
            if matchObj:
                exid = matchObj.group(1)
                if not fix_external_ids:
                    exidstr = (
                        ". Maybe %s? add --fix-external-ids to automatically populate it"
                        % (termcolor.colored(exid, "cyan"))
                    )
                else:
                    exidstr = ". Fixing with %s" % (exid)
            if output_format != "csv":
                print(
                    "Node %s lacks an external_id, name %s%s"
                    % (n["id"], n["name"], exidstr)
                )
            if fix_external_ids and exid:
                ug.update_devices([n], {"external_id": exid}, debug)


def findNodes(
    args: argparse.Namespace,
    core: Core,
    ug: Upguard,
):
    connector = core.connector
    nodes = []
    if args.ticket:
        nodes = core.searchTicketComputers(connector, args.ticket, args.debug)

        if len(nodes):
            nodes = core.filter(nodes, args)
            print("")
    else:
        if isinstance(args.IDS, list) and len(args.IDS):  # work on array of IDS
            nodes = ug.searchByIDS(args.IDS, debug=args.debug)
        elif isinstance(args.CoreIDS, list) and len(
            args.CoreIDS
        ):  # work on array of Core IDS
            nodes = ug.searchByCoreIDS(args.CoreIDS, debug=args.debug)
        elif args.os_filter == "all":
            nodes = ug.index(args.debug)

        if args.os_filter == "linux":
            if len(nodes) == 0:
                nodes = ug.SearchByLinux(debug=args.debug)
            else:
                nodes = ug.filterByLinux(nodes, args.debug)
        elif args.os_filter == "windows":
            if len(nodes) == 0:
                nodes = ug.SearchByWindows(debug=args.debug)
            else:
                nodes = ug.filterByWindows(nodes, args.debug)

    return nodes


def main():
    connector = None
    ug = None
    command_args = parse_cli()
    if command_args.debug:
        print("ARGS: " + pformat(command_args))
    if command_args.loglevel:
        LOGLEVEL = command_args.loglevel.upper()
    else:
        LOGLEVEL = os.environ.get('LOGLEVEL', 'WARNING').upper()
    logging.basicConfig(format='%(levelname)s:%(message)s', level=LOGLEVEL)

    nodes = []

    core = Core()
    connector = core.login(
        debug=command_args.debug, rackertoken=command_args.rackertoken
    )
    if not connector:
        logging.fatal("Can't authenticate  to CORE, exiting")
        exit(1)

    if command_args.account:
        credentials = get_ug_credentials(core, command_args.account)
        if credentials:
            ug = Upguard(**credentials)
            if not ug:
                logging.fatal(
                    "Couldn't initialize Upguard connection. Please check the credentials in passwordsafe and try again"
                )
                exit(1)
            logging.info(f"Upguard Credentials retrieved for account {command_args.account} ({credentials['description']})")
            if command_args.show_credentials:
                print("=" * 80)
                print(credentials["description"] + ": Upguard Credentials")
                print("=" * 80)
                for key, value in credentials.items():
                    print(f"{key: <30}{value}")
                print("=" * 80)
        else:
            print("UpGuard credentials not found")
    try:
        logging.debug("calling findNodes")
        nodes = findNodes(command_args, core, ug)
    except:
        logging.fatal("Couldn't retrieve nodes from Upguard: EXIT")
        exit(1)

    if command_args.showConnectionManagers:
        ug.showCMS(command_args.debug)

    if command_args.showUsers:
        ug.showUsers(command_args.debug)

    if command_args.showConnectionManagerGroups:
        ug.showCMGS(command_args.debug)

    if command_args.checkCMS:
        ug.checkCMS(command_args.debug)

    if command_args.showEnvironments:
        ug.showEnvironments(command_args.debug)

    if command_args.ticket:
        if isinstance(command_args.data, dict):
            dt = command_args.data
        else:
            dt = {}
        if command_args.adds:
            ug.add_core_nodes(nodes, dt, command_args.debug)
        elif command_args.updates and dt:
            ug.update_core_devices(nodes, dt, command_args.debug)
        elif command_args.deletes:
            ug.delete_core_devices(nodes, command_args.debug)
        elif command_args.replaceNameWithNatIP:
            # simulate an update with a preformatted data in json format
            for n in nodes:
                dt = {"medium_hostname": n["primary_nat_ip"]}
                ug.update_core_devices([n], dt, command_args.debug)
        elif command_args.replaceNameWithFQDN:
            # simulate an update with a preformatted data in json format
            for n in nodes:
                dt = {"medium_hostname": n["name"]}
                ug.update_core_devices([n], dt, command_args.debug)
    else:  # not working on tickets, but on CoreIDS/IDS specified in the command line
        if command_args.showNodes:
            show_nodes(ug, nodes, command_args)

        if command_args.adds:
            add_nodes(ug, core, command_args)
        elif command_args.updates and isinstance(command_args.data, dict):
            ug.update_devices(nodes, command_args.data, command_args.debug)  # FIXME
        elif command_args.deletes:
            ug.delete_devices(nodes, command_args.debug)
        elif command_args.replaceNameWithFQDN or command_args.replaceNameWithNatIP:
            ug.fixNatFqdn(core, command_args, nodes, command_args.debug)
        elif command_args.scanNode:
            for n in nodes:
                j = ug.scanNode(n["id"], command_args.debug)
                if j:
                    print("Job: %s" % (j))
        elif command_args.audit:
            if not command_args.account:
                print("Can't audit without an account number")
                exit(1)
            show_audit(
                core,
                ug,
                account_num=command_args.account,
                mismatch_filter=command_args.mismatch_filter,
                fix_external_ids=command_args.fix_external_ids,
                output_format=command_args.output_format,
                check_sku=command_args.check_sku,
                os_filter=command_args.os_filter,
                debug=command_args.debug,
            )
        elif command_args.showNodeGroups:
            ug.showNodeGroups(command_args.debug)
        elif command_args.nodeGroupRemoveNodes:
            ug.nodeGroupRemoveNodes(nodes, command_args.debug)
        elif command_args.moveNodesToSuspended:
            ug.moveNodesToSuspended(nodes, command_args.debug)


if __name__ == "__main__":
    main()
