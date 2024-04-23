# ugtool.py : A command line tool to add/update/delete servers and devices in Upguard.

## INSTALLATION
Clone the repo:
```
$ git clone  https://githubcom/rajiv641/upguardTools.git
# OR
$ git clone  git@github.com:rajiv641/upguardTools.git
```

Ensure pip can find the librack2 libraries:

```
$ vi ~/.config/pip/pip.conf #(Or possibly ~/.pip/pip.conf depending on distro)
--------
[global]
extra-index-url =
    https://artifacts.rackspace.net/artifactory/api/pypi/pypi/simple

trusted-host =
    artifacts.rackspace.net
    github.rackspace.com

-------
```
Install librack2 (probably already be installed if you have hammertime):
```
pip install librack2
```

Install remaining requirements:
```
pip install --user -r requirements.txt
```

## CONFIGURATION:

We have updated this version of upguardTools to retrieve credentials from passwordsafe instead of using configuration files.

Credentials for each instance/account should be stored in project 18316 of passwordsafe under the 'api_keys' tab:
https://passwordsafe.corp.rackspace.com/projects/18316

**NOTE: You will need access to this passwordsafe project in order to successfully use the tool**

Passwordsafe fields do not correspond to the information we need to login to an upguard instance, so when entering new upguard server 
details you need to map the information as follows: 

| Passwordsafe Field    | What you enter from Upguard/core  | Example                                  |
| --------------------- | --------------------------------- | ---------------------------------------- |
| Category:             | Just `api_keys`                   | `api_keys`                               |
| Description:          | (Copy the account Name from core) | Acme Coyote Provisioning Services (ACPS) |
| Hostname:             | (CORE Account number)             | 999999                                   |
| Url:                  | (The url of the upguard server)   | https://999999.configdrift.com           |
| Username:             | (The upguard api key)             | 65xxxxxxxxxxxxxxxx...xxxxxxxxxxxxxxxxxfc |
| Password:             | (The upguard api secret)          | c6xxxxxxxxxxxxxxxx...xxxxxxxxxxxxxxxxx0d |


The keys can be retrieved from the configdrift site for the account, clicking the top right corner and following the link for 'Manage accounts'->'ACCOUNT NAME'.

## EXAMPLE USAGE

Get help on the tool:
```
$ cd upguardTools
$ python ugtool.py --help to have a full list of options.
```
(Options can be specified with both short or long forms, for example -i/--ids, -a/--add and -u/--update)

Perform an Audit of the devices belonging to the given account and shows which are defined or undefined in Upguard:
```
$ python ugtool.py  -A 999999 --account 1234567 --audit

# You can use (long form:--mismatch-filter) `-M missing`  to show only the missing items, or `-M present`` to show only items that are present. 
# You can also limit the audit to specific os types with --os-filter=linux or --os-filter=windows

$ python ugtool.py  -A 999999 --account 1234567 --audit --os-filter windows -M present

# To check whether the configuration management SKU has been assigned to each device use the -K/--check-sku option

```
**(NOTE: --audit option is the most througoughly tested recently. Use the options below with caution and report any issues)**

Adds all devices in ticket 180712-06660 to upguard:
```
$ python ugtool.py -A 999999 --ticket 180712-06660 --all 
```

List of users in an Active Upguard Account:
```
$ python ugtool.py -A 999999 --show-user
```

Updates the Linux nodes to use the CM with ID 6:
```
$ python ugtool.py -A 999999 --ticket 180712-06660 --linux --data '{"connection_manager_group_id": 6}' --update 
```

Delete all windows devices linked in ticket 180712-06660 from Upguard:
```
$ python ugtool.py -A 999999 --ticket 180712-06660 --windows --delete
```

Show all configured nodes:
```
$ python ugtool.py -A 999999 --show --all
```

Show a summary of devices with Upguard ids 39, 40 and 41:
```
$ python ugtool.py -A 999999 --show --ids 39 40 41 
```

Delete devices with CORE ids 918778 and 918779 from Upguard, enabling debug mode:
```
$ python ugtool.py  -A 999999 --delete --coreids 918778  918779 --debug
```

Perform a SCAN on a node with COREID 123456 and print the job id:
```
$ python ugtool.py  -A 999999 --scan --coreids 123456
```

Update the nodes in ticket 180712-06660 for Account 123456, overwriting the hostname with the nat_private_ip address registered in CORE:
```
$ python ugtool.py  -A 999999 --account 123456 --ticket 180712-06660 --nat
```

Update the nodes in ticket 180712-06660 for Account 123456, overwriting the medium_hostname with the FQDN registered in CORE:
```
$ python ugtool.py  -A 999999 --account 123456 --ticket 180712-06660 --fqdn
```

Show the list of environments:
```
$ python ugtool.py  -A 999999 --show-envs
```

Suspend the given node moving it to the SUSPENDED environment:
```
$ python ugtool.py  -A 999999 --susp -c 999999
```

Show the list of connection managers:
```
$ python ugtool.py  -A 999999  --show-cms
```

Show the list of connection manager groups:
```
$ python ugtool.py  -A 999999  --show-cmgs
```

Check the health of the connection managers:
```
$ python ugtool.py  -A 999999  --check-cms
```
(The above command can be used in a cron job to report incidents on the connection managers.)


NOTE:

When using -a/--add or -u/--update you can specify a list of attributes to set with --data, in JSON format, as in:
`--data '{"connection_manager_group_id": 6, "username": "upguard", "password": "pincopallino"}'`

Only a small subset of attributes can be set; all the others will be refused.
The list is in the ugtool.py source.


## SUPPORT
For assistance contact: cse_lin@rackspace.co.uk
