import time
from cxsupport import CxOneClient
from cxsupport import CxSastClient
from logsupport import logger
from pathlib import Path

import configparser  
import argparse

def confirm(prompt="Are you ABSOLUTELY sure? (y/n): "):
    return input(prompt).strip().lower() == 'y'

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

# CxOne Config
iam_host = config['CXONE']['iam_host']
ast_host = config['CXONE']['ast_host']
tenant = config['CXONE']['tenant']
api_key = config['CXONE']['api_key']

logger.debug(f"-------------------------------------------------------------")
logger.debug(f"Project, Application cleaner")
logger.debug(f"Target: {ast_host}")
logger.debug(f"{'REAL EXECUTION MODE' if is_exec else 'DRY-RUN MODE'}")
logger.debug(f"-------------------------------------------------------------")

logger.debug(f"Initializing CxOne client...")
# Initialize CxOne client
cxone_client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

# Find CxOne applications
logger.debug("Fetching CxOne Applications...")
cxone_applications_dict = cxone_client.get_applications_dict()
n_apps = len(cxone_applications_dict)
logger.debug(f'Found: {n_apps}')
# for idx, app in enumerate(cxone_applications_dict):
#    logger.debug(f'   {app}: {cxone_applications_dict[app]}')

# Find CxOne projects
logger.debug("Fetching CxOne projects...")
cxone_projects_dict = cxone_client.get_projects_dict()
n_projs = len(cxone_projects_dict)
logger.debug(f'Found: {n_projs}')
# for idx, project in enumerate(cxone_projects_dict):
#    logger.debug(f'   {project}: {cxone_projects_dict[project]}')

if n_projs == 0 and n_apps == 0:
    logger.debug(f"Nothing to do. Done.")
    exit(0)

logger.debug(f"{n_projs} projects and {n_apps} applications will be DELETED from CxOne tenant [{tenant}]")
if is_exec and not confirm():
    exit (0)


logger.debug(f'--------------------------------------------')
logger.debug(f'Deleting Projects')

idx = 1
for name, id in cxone_projects_dict.items():
    logger.debug(f"{idx} Deleting CxOne Project [{name}, id: {id}]")
    if is_exec:
        cxone_client.delete_project(id)
    idx += 1

logger.debug(f'--------------------------------------------')
logger.debug(f'Deleting Applications')

idx = 1
for name, id in cxone_applications_dict.items():
    logger.debug(f"{idx} Deleting CxOne Application [{name}, id: {id}]")
    if is_exec:
        cxone_client.delete_application(id)
    idx += 1

logger.debug("Done.")