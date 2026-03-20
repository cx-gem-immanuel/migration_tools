# Custom Tools for CxSAST to CxOne Migration

**Note**: All scripts run in Dry-Run mode by default.

An explicit --exec parameter must be supplied for real execution.

## CxOne Projects and Applications Cleanup/Deletion 
Deletes Projects and Applications from configured CxOne tenant. 

Two options are offered:
- Delete ALL Projects and Applications
OR
- Delete select Projects and Applications, supplied by a CSV file. 

*A CSV file can be generated from the CxSAST Project Listing page (CSV export). It MUST contain 'Project Name' and 'Team' Columns. The 'Team' path's terminal part is used to compute the Application Name. Ex. CxServer/Some/Path/**BuildTools***


**Usage**
```shell
λ py clean.py -h
usage: clean.py [-h] [--exec] --config CONFIG [--projects PROJECTS]

Configuration

options:
  -h, --help            show this help message and exit
  --exec, -exec         Execution mode.
  --config CONFIG, -c CONFIG
                        Path to the configuration file to read
  --projects PROJECTS, -p PROJECTS
                        Path to the CSV file containing projects to delete
```
**Sample Execution:**
```shell
py clean.py --config myConfig.ini 
or
py clean.py --config myConfig.ini --projects projects_to_delete.csv
```

```shell
λ py clean.py --config my_config.ini
2026-03-19 22:46:44,410 - DEBUG - -------------------------------------------------------------
2026-03-19 22:46:44,411 - DEBUG - Project, Application cleaner
2026-03-19 22:46:44,412 - DEBUG - Target: https://ast.checkmarx.net
2026-03-19 22:46:44,413 - DEBUG - DRY-RUN MODE
2026-03-19 22:46:44,413 - DEBUG - -------------------------------------------------------------
2026-03-19 22:46:44,413 - DEBUG - Initializing CxOne client...
2026-03-19 22:46:44,414 - DEBUG - Fetching CxOne Applications...
2026-03-19 22:46:45,191 - DEBUG - Fetching CxOne projects...
2026-03-19 22:46:45,491 - DEBUG - There are 10 existing Projects in CxOne.
2026-03-19 22:46:45,492 - DEBUG - There are 6 existing Applications in CxOne.
2026-03-19 22:46:45,493 - DEBUG - --------------------------------------------
2026-03-19 22:46:45,494 - DEBUG - Deleting Projects
2026-03-19 22:46:45,494 - DEBUG - 1 Deleting CxOne Project [MFD-PAGS-S2iBanknet, id: f0333b7d-458b-4389-b438-0ece194a7104]
2026-03-19 22:46:45,494 - DEBUG - 2 Deleting CxOne Project [101624-rearau-ide-raa-site, id: 8f7f92e4-eedd-40d5-8564-3ca5981c41ab]
2026-03-19 22:46:45,495 - DEBUG - 3 Deleting CxOne Project [SpaceX/GNC/Guidance/DVJA, id: 8a0bcf76-21e2-4dc5-b933-8a6f51052c13]
2026-03-19 22:46:45,495 - DEBUG - 4 Deleting CxOne Project [NASA/fprime, id: ba81b05b-42ae-412b-8c27-3034dbb24403]
2026-03-19 22:46:45,495 - DEBUG - 5 Deleting CxOne Project [NASA/condor, id: 88f28a28-f1ab-4cf1-9f94-4ec0a7d02b9e]
2026-03-19 22:46:45,495 - DEBUG - 6 Deleting CxOne Project [SpaceX/Starship, id: 5ed86fe5-03ef-4737-a71d-b298ceb69e1e]
2026-03-19 22:46:45,495 - DEBUG - 7 Deleting CxOne Project [SpaceX/Telemetrics/TMSConsole, id: 1d0b2df8-4ecc-4392-8847-444ded84e8ae]
2026-03-19 22:46:45,495 - DEBUG - 8 Deleting CxOne Project [SpaceX/GNC/Guidance/HNAVSystem, id: fab11134-b15d-40f7-ba42-152a2e8e373d]
2026-03-19 22:46:45,496 - DEBUG - 9 Deleting CxOne Project [SpaceX/GNC/FlightConsole, id: 0b9f4607-dba7-4948-b406-21c3ecd438da]
2026-03-19 22:46:45,496 - DEBUG - 10 Deleting CxOne Project [SpaceX/GNC/Navigation/GPS3, id: a63f9cc3-cbf8-4e1b-b1df-3f0803ce3d6b]
2026-03-19 22:46:45,496 - DEBUG - --------------------------------------------
2026-03-19 22:46:45,496 - DEBUG - Deleting Applications
2026-03-19 22:46:45,496 - DEBUG - 1 Deleting CxOne Application [SPACEX_GUIDANCE, id: 8f5a84e0-2ce8-41bf-b8a5-a2f44480a0cb]
2026-03-19 22:46:45,496 - DEBUG - 2 Deleting CxOne Application [SPACEX_TELEMETRICS, id: b6cdba05-242f-40fe-889b-49568c455a9a]
2026-03-19 22:46:45,496 - DEBUG - 3 Deleting CxOne Application [SPACEX_GNC, id: a3a2a6ec-33df-4d3c-a1fc-3e0e0b4624e9]
2026-03-19 22:46:45,497 - DEBUG - 4 Deleting CxOne Application [NASA, id: 556a9a48-bcb6-4f33-8e3f-98f459e3cdf9]
2026-03-19 22:46:45,497 - DEBUG - 5 Deleting CxOne Application [SPACEX, id: 722c804e-b14d-4cfd-8018-87d9fa42ba36]
2026-03-19 22:46:45,497 - DEBUG - 6 Deleting CxOne Application [SPACEX_NAVIGATION, id: 74bdef1b-6194-475d-9ac2-52129ae37d65]
2026-03-19 22:46:45,497 - DEBUG - --------------------------------------------
2026-03-19 22:46:45,497 - DEBUG - Summary:
2026-03-19 22:46:45,497 - DEBUG - Deleted 10 Projects from CxOne tenant [gemi].
2026-03-19 22:46:45,497 - DEBUG - Deleted 6 Applications from CxOne tenant [gemi].
2026-03-19 22:46:45,498 - DEBUG - Done.
```

------------



## CxOne Groups Creation Automation
Creates CxOne Groups from CxSAST LDAP Group Mapping.

The CxOne Group name is computed as the common name (CN) part of the LDAP Distinguished Name (DN) assigned to a given CxSAST team.

**Example**
If "CN=developers,OU=Groups,OU=IT,DC=example,DC=com" is mapped to "CxServer/Some/Path/developers", "developers" (the CN part of the LDAP DN) will be used as the CxOne Group Name.

**Note:**
If the script is re-run, 
- CxOne Groups that do not exist will be created. 
- Currently assigned Roles will be *replaced* by given Roles.

**Usage**
```shell
λ py create-groups.py -h
usage: create-groups.py [-h] [--exec] --config CONFIG --default-roles DEFAULT_ROLES

Configuration

options:
  -h, --help            show this help message and exit
  --exec, -exec         Execution mode.
  --config CONFIG, -c CONFIG
                        Path to the configuration file to read
  --default-roles DEFAULT_ROLES, -r DEFAULT_ROLES
                        Default roles (comma-separated) to assign to groups
```
**Sample Execution:**
```shell
λ py create-groups.py --config my_config.ini -r "ast-viewer,my-custom-role"
2026-03-19 22:56:48,295 - DEBUG - -------------------------------------------------------------
2026-03-19 22:56:48,295 - DEBUG - Groups Creation
2026-03-19 22:56:48,296 - DEBUG - Source: https://fis.checkmarx.net
2026-03-19 22:56:48,296 - DEBUG - Target: https://ast.checkmarx.net
2026-03-19 22:56:48,296 - DEBUG - DRY-RUN MODE
2026-03-19 22:56:48,297 - DEBUG - -------------------------------------------------------------
2026-03-19 22:56:48,297 - DEBUG - Initializing CxSAST and CxOne clients...
2026-03-19 22:56:48,568 - DEBUG - Fetching LDAP groups...
2026-03-19 22:56:48,569 - DEBUG - Found: 5
2026-03-19 22:56:48,951 - WARNING - Given role [my-custom-role] was not found in tenant [gemi]. Will not assign this role to any groups. Please check the role name on CxOne.
2026-03-19 22:56:49,183 - DEBUG - Group [propulsion] was created.
2026-03-19 22:56:49,184 - DEBUG - Group [avionics] was created.
2026-03-19 22:56:49,184 - DEBUG - Group [flight-software] was created.
2026-03-19 22:56:49,185 - DEBUG - Group [structural] was created.
2026-03-19 22:56:49,185 - DEBUG - Group [launch-operations] was created.
2026-03-19 22:56:49,286 - DEBUG - Role(s) ['ast-viewer'] assigned to group [propulsion].
2026-03-19 22:56:49,287 - DEBUG - Role(s) ['ast-viewer'] assigned to group [avionics].
2026-03-19 22:56:49,287 - DEBUG - Role(s) ['ast-viewer'] assigned to group [flight-software].
2026-03-19 22:56:49,287 - DEBUG - Role(s) ['ast-viewer'] assigned to group [structural].
2026-03-19 22:56:49,287 - DEBUG - Role(s) ['ast-viewer'] assigned to group [launch-operations].
2026-03-19 22:56:49,287 - DEBUG - --------------------------------------------
2026-03-19 22:56:49,288 - DEBUG - Summary:
2026-03-19 22:56:49,288 - DEBUG - Groups created: 5
2026-03-19 22:56:49,288 - DEBUG - Groups already existing: 0
2026-03-19 22:56:49,288 - DEBUG - Groups assigned roles: 5
2026-03-19 22:56:49,288 - DEBUG - Done.
```
------------

## Project => Application Mapping and Application => Group Authorization Automation
Automatically maps CxOne Projects to computed Applications (creating them if needed) and Authorizing them to computed Groups.

The CxOne Application Name is computed from the leaf element of the CxSAST team path. 
Ex. CxServer/Some/Path/BuildTools => CxOne Application "BuildTools"
All projects that belong to a given team, will be associated to the computed Application.

The CxOne Group Name is computed from the CN of the LDAP DN mapped to a CxSAST team.
Ex. CN=EliteGroup,OU=Groups,OU=IT,DC=example,DC=com is mapped to CxServer/Some/Path/BuildTools 
"EliteGroup" (CN part of the LDAP DN) will be used as the CxOne Group Name.

**Example Mapping and Authorization**
The complete mapping authorization (examples from above) will look like:
All projects under CxServer/Some/Path/BuildTools will be associated with CxOne Application 'BuildTools'.
The 'BuildTools' Appplication will be authorized to the CxOne Group 'EliteGroup'.

**Usage**

```shell
λ py main.py -h
usage: main.py [-h] [--exec] --config CONFIG

Configuration

options:
  -h, --help            show this help message and exit
  --exec, -exec         Execution mode.
  --config CONFIG, -c CONFIG
                        Path to the configuration file to read
```

**Sample Execution:**
```shell
λ py main.py --config my_config.ini
2026-03-19 23:38:08,610 - DEBUG - -------------------------------------------------------------
2026-03-19 23:38:08,611 - DEBUG - Project > Application > Group mapping and Authorization
2026-03-19 23:38:08,612 - DEBUG - Source: https://hello.checkmarx.net
2026-03-19 23:38:08,613 - DEBUG - Target: https://ast.checkmarx.net
2026-03-19 23:38:08,613 - DEBUG - DRY-RUN MODE
2026-03-19 23:38:08,613 - DEBUG - -------------------------------------------------------------
2026-03-19 23:38:08,614 - DEBUG - Initializing CxSAST and CxOne clients...
2026-03-19 23:38:08,615 - DEBUG - Fetching CxSAST teams...
2026-03-19 23:38:09,320 - DEBUG - Found: 274
2026-03-19 23:38:09,321 - DEBUG - Fetching CxSAST projects...
2026-03-19 23:38:22,199 - DEBUG - Found: 1590
2026-03-19 23:38:22,200 - DEBUG - Fetching LDAP groups...
2026-03-19 23:38:22,201 - DEBUG - Found: 272
2026-03-19 23:38:22,201 - DEBUG - Fetching CxOne Applications...
2026-03-19 23:38:22,533 - DEBUG - Found: 6
2026-03-19 23:38:22,534 - DEBUG - Fetching CxOne projects...
2026-03-19 23:38:22,869 - DEBUG - Found: 14
2026-03-19 23:38:22,870 - DEBUG - Fetching CxOne groups...
2026-03-19 23:38:23,162 - DEBUG - Found: 7
2026-03-19 23:38:23,164 - DEBUG - --------------------------------------------
2026-03-19 23:38:23,164 - DEBUG - ...Skipping. CxSAST project [project-guidance] was not found on CxOne.
2026-03-19 23:38:23,164 - DEBUG - Processing CxSAST project [CapStone], team: [175, /CxServer/Internal/Propulsion], CxOne project id [df5668d2-d61d-4fff-a46d-5b4a50342901]
2026-03-19 23:38:23,165 - DEBUG - Creating CxOne Application [Propulsion]
2026-03-19 23:38:23,165 - DEBUG - Associated project [CapStone] with application [Propulsion].
2026-03-19 23:38:23,165 - DEBUG - Authorized application [Propulsion] for group [propulsion]
2026-03-19 23:38:23,166 - DEBUG - ...Skipping. CxSAST project [tlc-console] was not found on CxOne.
...
2026-03-19 23:38:23,168 - DEBUG - Processing CxSAST project [RealEstate], team: [229, /CxServer/Internal/Structural], CxOne project id [21790f63-7e50-4976-b623-0972e2840b74]
2026-03-19 23:38:23,169 - DEBUG - Creating CxOne Application [Structural]
2026-03-19 23:38:23,169 - DEBUG - Associated project [RealEstate] with application [Structural].
2026-03-19 23:38:23,169 - DEBUG - Authorized application [Structural] for group [structural]
...
2026-03-19 23:38:23,169 - DEBUG - --------------------------------------------
2026-03-19 23:38:23,169 - DEBUG - Summary:
2026-03-19 23:38:23,170 - DEBUG - Created 4 applications.
2026-03-19 23:38:23,170 - DEBUG - Associated 4 projects to applications.
2026-03-19 23:38:23,170 - DEBUG - Authorized 4 applications.
```
