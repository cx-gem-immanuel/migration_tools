from cxsupport import CxOneClient
from cxsupport import CxSastClient
from logsupport import logger

import configparser  
import argparse

# Client name of the AST APP
AST_APP_CLIENT_NAME = "ast-app"

# ========================================== Main Execution ==========================================

parser = argparse.ArgumentParser(description="Configuration")  

# Add argument for the config file path  
# Execution mode: default is dry run.
parser.add_argument('--exec', '-exec', action='store_true', default=False, help='Execution mode.', required=False)  
parser.add_argument('--config', '-c', type=str, help='Path to the configuration file to read', required=True)
parser.add_argument('--default-roles', '-r', type=str, help='Default roles (comma-separated) to assign to groups', required=True)

# Parse the arguments  
args = parser.parse_args()  

# args.default_roles contains a csv string. Convert to array
default_roles = [role.strip() for role in args.default_roles.split(',')]
is_exec = args.exec

if args.config is None or args.config.strip() == '':
    logger.critical('Configuration file path is required.')
    exit(1)

config = configparser.ConfigParser()  
config.read(args.config) 

# CxSAST Config
cxsast_host = config['CXSAST']['host']
cxsast_username = config['CXSAST']['username']
cxsast_password = config['CXSAST']['password']

# CxOne Config
iam_host = config['CXONE']['iam_host']
ast_host = config['CXONE']['ast_host']
tenant = config['CXONE']['tenant']
api_key = config['CXONE']['api_key']

logger.debug(f"-------------------------------------------------------------")
logger.debug(f"Groups Creation")
logger.debug(f"Source: {cxsast_host}")
logger.debug(f"Target: {ast_host}")
logger.debug(f"{'REAL EXECUTION MODE' if is_exec else 'DRY-RUN MODE'}")
logger.debug(f"-------------------------------------------------------------")

logger.debug(f"Initializing CxSAST and CxOne clients...")
# Initialize CxSAST client
cxsast_client = CxSastClient(cxsast_host, cxsast_username, cxsast_password, False)
# Initialize CxOne client
cxone_client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

# Find the AST APP's client id
ast_app_client_id = cxone_client.get_client_id(AST_APP_CLIENT_NAME)
if ast_app_client_id is None:
    logger.error(f"Cannot find the [{AST_APP_CLIENT_NAME}] client in access control. Please contact Checkmax Support.")
    exit(1)

# Find CxSAST LDAP groups
logger.debug("Fetching LDAP groups...")
cxsast_ldap_groups_dict = cxsast_client.get_ldap_groups_dict()
logger.debug(f'Found: {len(cxsast_ldap_groups_dict)}')
# Debugging aid:
# for group in cxsast_ldap_groups_dict:
#    logger.debug(f'   {group}: {cxsast_ldap_groups_dict[group]}')

# -----------------------------------------------------------------------------------
roles_to_assign = []
# Create desired composite role if it doesn't already exist
for role_name in default_roles:
    role_id = cxone_client.get_role_id(ast_app_client_id, role_name)
    if role_id is None:
        logger.warning(f"Given role [{role_name}] was not found in tenant [{tenant}]. Will not assign this role to any groups. Please check the role name on CxOne.")
        continue
    # Add desired roles to array.
    roles_to_assign.append({"id": role_id, "name": role_name})

rolenames_to_assign = [role["name"] for role in roles_to_assign]

# -----------------------------------------------------------------------------------
# Create CxOne groups from the current CxSAST LDAP group mapping data
# CxOne group name is the CN value of the DN from the LDAP group mapping
n_groups_created = 0
n_groups_existing = 0
cxone_groups_dict = cxone_client.get_groups_dict()
for cxone_group in cxsast_ldap_groups_dict.values():
        
    # Create desired group if it doesn't exist
    if cxone_group in cxone_groups_dict.keys():
        logger.debug(f"CxOne group [{cxone_group}] already exists.")
        n_groups_existing += 1
    else:
        group_created = True
        if is_exec:
            group_created = cxone_client.create_group(cxone_group)        
        if group_created:
            logger.debug(f"Group [{cxone_group}] was created.")
            n_groups_created += 1
        else:
            logger.error(f"Group [{cxone_group}] creation failed.")

# Refresh groups dictionary
cxone_groups_dict = cxone_client.get_groups_dict()

# -----------------------------------------------------------------------------------
# Assign roles to group
# Get the group ID for the newly created group
n_roles_assigned = 0
for cxone_group in cxsast_ldap_groups_dict.values():
    group_id = 0 if not is_exec else cxone_groups_dict[cxone_group]
    if group_id is not None:
        role_assigned = True 
        if is_exec:
            # Clear out roles first
            roles_cleared = cxone_client.delete_roles_in_group(group_id, ast_app_client_id)
            if not roles_cleared:
                logger.warning(f"Could not clear existing roles in group {cxone_group}. Given role(s) will be appended instead.")
            role_assigned = cxone_client.assign_roles_to_group(group_id, ast_app_client_id, roles_to_assign)
        if role_assigned:
            logger.debug(f"Role(s) {rolenames_to_assign} assigned to group [{cxone_group}].")
            n_roles_assigned += 1
        else:
            logger.error(f"Failed to assign role(s) {rolenames_to_assign} to group [{cxone_group}].")
    else:
        logger.error(f"Failed to retrieve group [{cxone_group}] for role assignment.")       

# Print summary
logger.debug(f'--------------------------------------------')
logger.debug(f"Summary:")
logger.debug(f"Groups created: {n_groups_created}")
logger.debug(f"Groups already existing: {n_groups_existing}")
logger.debug(f"Groups assigned roles: {n_roles_assigned}")
logger.debug("Done.")