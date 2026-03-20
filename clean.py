import time
from cxsupport import CxOneClient
from cxsupport import CxSastClient
from logsupport import logger
from pathlib import Path

import configparser  
import argparse
import csv

def confirm(prompt="Are you ABSOLUTELY sure? (y/n): "):
    return input(prompt).strip().lower() == 'y'

# ========================================== Main Execution ==========================================

parser = argparse.ArgumentParser(description="Configuration")  

# Add argument for the config file path  
# Execution mode: default is dry run.
parser.add_argument('--exec', '-exec', action='store_true', default=False, help='Execution mode.', required=False)  
parser.add_argument('--config', '-c', type=str, help='Path to the configuration file to read', required=True)  
parser.add_argument('--projects', '-p', type=str, help='Path to the CSV file containing projects to clean', required=False)

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

# CSV file has Project Name, Owner, Team, Preset, Total Scans, Last Scanned
# Generate a list of project names from the CSV File
projects_to_delete = set()
applications_to_delete = set()
if args.projects:
    try:
        with open(args.projects, 'r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                projects_to_delete.add(row['Project Name'].strip().lower())
                applications_to_delete.add(Path(row['Team'].strip()).name.lower())
    except FileNotFoundError:
        logger.error(f"Projects CSV file not found: {args.projects}")
        exit(1)
    except KeyError:
        logger.error("CSV file must contain 'Project Name' and 'Team' columns")
        exit(1)

# Are we working with a CSV list of projects/applications to delete 
# or ALL projects and applications from tenant?
csv_provided = len(projects_to_delete) > 0 or len(applications_to_delete) > 0

logger.debug(f"Initializing CxOne client...")
# Initialize CxOne client
cxone_client = CxOneClient(iam_host, ast_host, tenant, api_key, False)

# Find CxOne applications
logger.debug("Fetching CxOne Applications...")
cxone_applications_dict = cxone_client.get_applications_dict()
n_cxone_apps = len(cxone_applications_dict)

# Find CxOne projects
logger.debug("Fetching CxOne projects...")
cxone_projects_dict = cxone_client.get_projects_dict()
n_cxone_projs = len(cxone_projects_dict)

if n_cxone_projs == 0 and n_cxone_apps == 0:
    logger.debug(f"Nothing to do. Done.")
    exit(0)

# Number of Projects to Delete
npd = len(projects_to_delete) if csv_provided else n_cxone_projs
# Number of Applications to Delete
nad = len(applications_to_delete) if csv_provided else n_cxone_apps

if csv_provided:
    logger.debug(f"The given CSV file lists {len(projects_to_delete)} Projects to delete.")
    logger.debug(f"The given CSV file lists {len(applications_to_delete)} Applications to delete.")
logger.debug(f'There are {n_cxone_projs} existing Projects in CxOne.')
logger.debug(f'There are {n_cxone_apps} existing Applications in CxOne.')

# Request explicit confirmation before proceeding
if is_exec and not confirm():
    exit (0)

logger.debug(f'--------------------------------------------')
logger.debug(f'Deleting Projects')

n_matched_projects = 0
pidx = 1
for name, id in cxone_projects_dict.items():
    if csv_provided and name.lower() not in projects_to_delete:        
        continue
    n_matched_projects += 1
    logger.debug(f"{pidx} Deleting CxOne Project [{name}, id: {id}]")
    if is_exec:
        cxone_client.delete_project(id)
    pidx += 1

logger.debug(f'--------------------------------------------')
logger.debug(f'Deleting Applications')

n_matched_applications = 0
aidx = 1
for name, id in cxone_applications_dict.items():
    if csv_provided and name.lower() not in applications_to_delete:
        continue
    n_matched_applications += 1
    logger.debug(f"{aidx} Deleting CxOne Application [{name}, id: {id}]")
    if is_exec:
        cxone_client.delete_application(id)
    aidx += 1

logger.debug(f'--------------------------------------------')
logger.debug(f"Summary:")
if csv_provided:
    logger.debug(f"Found {n_matched_projects} CxOne projects that matched list in given CSV file.")
logger.debug(f"Deleted {pidx-1} Projects from CxOne tenant [{tenant}].")

if csv_provided:
    logger.debug(f"Found {n_matched_applications} CxOne Applications that matched list in given CSV file.")
logger.debug(f"Deleted {aidx-1} Applications from CxOne tenant [{tenant}].")    

logger.debug("Done.")