import time
from cxsupport import CxOneClient
from cxsupport import CxSastClient
from logsupport import logger
from pathlib import Path

import configparser  
import argparse


def lookup(dictionary, key):
    if key in dictionary:
        return dictionary[key]
    return None

def get_application_name(full_team_path):
    #   application name is leaf in team path
    #       ex. /a/b/c/app_name
    return Path(full_team_path).name    

ignored_teams = ['TEST']

# ========================================== Main Execution ==========================================

parser = argparse.ArgumentParser(description="Configuration")  

# Add argument for the config file path  
# Execution mode: default is dry run.
parser.add_argument('--exec', '-exec', action='store_true', default=False, help='Execution mode.', required=False)  
parser.add_argument('--config', '-c', type=str, help='Path to the configuration file to read', required=True)  

# Parse the arguments  
args = parser.parse_args()  

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

logger.debug(f"Initializing CxSAST and CxOne clients...")
# Initialize CxSAST client
cxsast_client = CxSastClient(cxsast_host, cxsast_username, cxsast_password, False)
# Initialize CxOne client
cxone_client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

# Find CxSAST teams
logger.debug("Fetching CxSAST teams...")
cxsast_teams_dict =  cxsast_client.get_teams_dict()
logger.debug(f'Found: {len(cxsast_teams_dict)}')
# for idx, team in enumerate(cxsast_teams_dict):
#    logger.debug(f'   {team}: {cxsast_teams_dict[team]}')

# Find CxSAST projects
logger.debug("Fetching CxSAST projects...")
cxsast_projects = cxsast_client.get_projects()
logger.debug(f'Found: {len(cxsast_projects)}')
# for idx, project in enumerate(cxsast_projects):
#    logger.debug(f'   {project["name"]}: {project["teamId"]}')

# Find CxSAST LDAP groups
logger.debug("Fetching LDAP groups...")
cxsast_ldap_groups_dict = cxsast_client.get_ldap_groups_dict()
logger.debug(f'Found: {len(cxsast_ldap_groups_dict)}')
# for idx, group in enumerate(cxsast_ldap_groups_dict):
#    logger.debug(f'   {group}: {cxsast_ldap_groups_dict[group]}')

# Find CxOne applications
logger.debug("Fetching CxOne Applications...")
cxone_applications_dict = cxone_client.get_applications_dict()
logger.debug(f'Found: {len(cxone_applications_dict)}')
# for idx, app in enumerate(cxone_applications_dict):
#    logger.debug(f'   {app}: {cxone_applications_dict[app]}')

# Find CxOne projects
logger.debug("Fetching CxOne projects...")
cxone_projects_dict = cxone_client.get_projects_dict()
logger.debug(f'Found: {len(cxone_projects_dict)}')
# for idx, project in enumerate(cxone_projects_dict):
#    logger.debug(f'   {project}: {cxone_projects_dict[project]}')

# Find CxOne groups
logger.debug("Fetching CxOne groups...")
cxone_groups_dict = cxone_client.get_groups_dict()
logger.debug(f'Found: {len(cxone_groups_dict)}')
# for idx, group in enumerate(cxone_groups_dict):
#    logger.debug(f'   {group}: {cxone_groups_dict[group]}')


logger.debug(f'--------------------------------------------')

n_apps_created = 0
n_projects_mapped = 0
n_applications_authorized = 0

# For each CxSAST project,
#    Create application from team path's leaf element, if it doesn't exist
#    (Application's project-association rule will be via project-tags. Application name will be the project-tag value)
#    Lookup CxOne project and update it's project-tag with application name
for idx, cxsast_project in enumerate(cxsast_projects):

    # Lookup full team name from owning_team id
    team_id = cxsast_project['teamId']
    full_team_path = lookup(cxsast_teams_dict, team_id)

    if full_team_path is None:
        logger.warning(f"..... Skipping CxSAST project [{cxsast_project['name']}], team [{team_id}] not found")
        continue

    cxsast_project_name = cxsast_project['name']
    #logger.debug(f"{idx+1}. Processing CxSAST project [{cxsast_project_name}], team: [{team_id}, {full_team_path}]")

    # Lookup CxOne project id by name
    #   CxOne project name is the same as CxSAST project name
    cxone_project_id = lookup(cxone_projects_dict, cxsast_project_name)
    
    if cxone_project_id is None:
        #logger.warning(f"..... Skipping. CxSAST project [{cxsast_project_name}] was not found on CxOne.")
        continue
    
    logger.debug(f"Processing [{cxsast_project_name}, id: {cxone_project_id}]")

    # ---------------------------------------------
    # Create the CxOne Application
    #   association rule: project-tag
    #      project-tag is application_name
    # Determine CxOne application name from team path
    application_id = None
    application_name = get_application_name(full_team_path) 
    # Skip ignored teams
    if application_name in ignored_teams:
        logger.debug(f"Skipping CxOne Team [{application_name}]")
        continue
    logger.debug(f"Application Name [{application_name}]. Generated from CxSAST team [{full_team_path}]")
    application_id = lookup(cxone_applications_dict, application_name)
    if application_id is None:
        logger.debug(f"Creating CxOne Application [{application_name}]")
        n_apps_created += 1
        if is_exec:
            project_association_rules = [{ "type": "project.tag.key.exists", "value": f"{application_name}" }]
            application_id = cxone_client.create_application(application_name, None, 3, project_association_rules, None)
            # logger.debug(f"Adding {application_name} to cache.")
            cxone_applications_dict[application_name] = application_id    

    # ---------------------------------------------
    # Associate project with application
    #   Update project tag with application name
    if is_exec:
        cxone_client.update_project_tags(cxone_project_id, [f'{application_name}'])
    n_projects_mapped += 1
    logger.debug(f"Associated project [{cxsast_project_name}] with application [{application_name}].")

    # ---------------------------------------------
    # Authorize application to CxOne Group
    # We'll need: 
    #   CxOne Group Name which is the same as the CxSAST LDAP Group Name
    #   CxOne Group ID, which we can lookup by name
    group_name = lookup(cxsast_ldap_groups_dict, team_id)
    # Find the group id by name
    group_id = lookup(cxone_groups_dict, group_name)
    if group_id is None:
        logger.warning(f"WARNING: CxOne group [{group_name}] was not found. Cannot authorize application [{application_name}] to group.")        
        continue    
    if application_id is None:
        logger.warning(f"WARNING: CxOne application [id: {application_id}] was not found. Cannot authorize application [{application_name}] to group.")        
        continue    
    # Authorize application to group
    if is_exec:
        is_auth = cxone_client.is_authorized(application_id, group_id)
        if is_auth == 1:
            logger.debug(f"Application [{application_name}] is already authorized to group [{group_name}]")
            continue
        elif is_auth < 0:
            logger.warning(f"WARNING: Could not determine if application is already authorized to requested group.")
            continue
        elif is_auth == 0:
            rc = cxone_client.authorize_application(application_id, group_id)
            if rc == 0:
                n_applications_authorized += 1
                logger.debug(f"Authorized application [{application_name}] for group [{group_name}]")
            else:
                logger.warning(f"WARNING: Could not authorize application [id:{application_id}, {application_name}] to group [id:{group_id}, {group_name}]")    


logger.debug(f"Created {n_apps_created} applications.")
logger.debug(f"Associated {n_projects_mapped} projects to applications.")
logger.debug(f"Authorized {n_applications_authorized} applications.")