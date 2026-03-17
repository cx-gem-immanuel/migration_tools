from datetime import datetime, timedelta
from email import header  
import requests
import json  
import time
import re
from logsupport import setup_logger  

logger = setup_logger()

class CxSastClient:
    def __init__(self, cxsast_host, username, password, is_verbose=False):

        self.username = username
        self.password = password
        self.cxsast_host = cxsast_host
        self.bearer_token = None
        self.is_verbose = is_verbose
        self.token_expiration = None
        self._teams_cache = {}        

    def get_bearer_token(self):

        if self.bearer_token is not None and datetime.now() < self.token_expiration:
            return self.bearer_token
        
        url = f'{self.cxsast_host}/cxrestapi/auth/identity/connect/token'
    
        data = {
            'username': self.username,
            'password': self.password,
            'grant_type': 'password',
            'scope': 'sast_rest_api',
            'client_id': 'resource_owner_client',
            'client_secret': '014DF517-39D1-4453-B7B3-9930C563627C'
        }

        # Send POST request to get the bearer token
        response = requests.post(url, data=data)  

        
        # If successful, return the access token
        if response.status_code == 200:  
            responseJson = response.json()
            expires_in = responseJson['expires_in']
            now = datetime.now()
            # 5 minute expiration buffer
            self.token_expiration = now + timedelta(seconds=expires_in - 300) 
            return response.json()['access_token'] 
        else:  
            # Print error if request failed
            logger.debug(f'Error: {response.status_code} - {response.text}')  
            return None

    def get_projects(self):

        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()

        url = f'{self.cxsast_host}/cxrestapi/projects'

        headers = {
            'Accept': 'application/json;v=5.0',
            'Authorization': f'Bearer {self.bearer_token}'
        }

        # Send GET request to list projects
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return None
    
    def get_teams_dict(self):
        
        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()

        url = f'{self.cxsast_host}/cxrestapi/auth/teams'

        headers = {
            'Accept': 'application/json;v=5.0',
            'Authorization': f'Bearer {self.bearer_token}'
        }

        # Send GET request to list teams
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            # [
            #   {
            #     "id": 0,
            #     "name": "string",
            #     "fullName": "string",
            #     "parentId": 0,
            #     "creationDate": "2026-03-13T02:55:36.957Z"
            #   }
            # ]
            # Create a dictionary of id to name
            teams_dict = {}
            for team in response.json():
                teams_dict[team['id']] = team['fullName']
            return teams_dict
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            return None

    def get_team_id(self, team_name):
        team_id = self._teams_cache.get(team_name, None)
        if team_id is not None: 
            return team_id        
        teams = self.get_teams_dict()
        for team in teams.get('teams', []):
            if team['fullname'] == team_name:
                team_id = team['id']
                self._teams_cache[team_name] = team_id
                break
        return team_id

    def get_ldap_groups_dict(self):

        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()

        # Construct the URL for listing LDAP groups
        url = f'{self.cxsast_host}/cxrestapi/auth/ldapteammappings'

        headers = {
            'Accept': 'application/json;v=5.0',
            'Authorization': f'Bearer {self.bearer_token}'
        }

        # Send GET request to list LDAP groups
        response = requests.get(url, headers=headers)
        
        ldap_groups_dict = {}
        
        if response.status_code == 200:
            # 200: returns
            #  [
            #   {
            #     "teamId": 0,
            #     "ldapGroupDn": "string",
            #     "ldapGroupDisplayName": "string",
            #     "id": 0,
            #     "ldapServerId": 0
            #   }
            # ]
            
            # Fetch the common name from given LDAP distinguished name
            def cn(dn):
                match = re.match(r'CN=([^,]+)', dn, re.IGNORECASE)
                return match.group(1) if match else None

            # Create a dictionary of teamId to ldapGroupDisplaName
            #   ex. {teamId: ldapGroupDisplayName}
            for ldap_group in response.json():
                dn = ldap_group['ldapGroupDn']
                cxone_group = cn(dn)
                ldap_groups_dict[ldap_group['teamId']] = cxone_group
            return ldap_groups_dict
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
        
        return ldap_groups_dict
        

        

class CxOneClient:
    def __init__(self, iam_host, ast_host, tenant, api_key, is_verbose=False):
        """
        Initialize the client with the specified IAM host, AST host, tenant, and API key.

        Args:
            iam_host (str): The IAM (Identity and Access Management) service host URL.
            ast_host (str): The AST (Application Security Testing) service host URL.
            tenant (str): The tenant identifier.
            api_key (str): The API key used for authentication.
        """
        # Initialize the client with required hosts, tenant, and API key
        self.api_key = api_key
        self.iam_host = iam_host
        self.ast_host = ast_host
        self.tenant = tenant
        self.bearer_token = None
        self.is_verbose = is_verbose
        self.token_expiration = None
        self._applications_cache = {}
        self._groups_cache = {}

    def get_bearer_token(self):
        """
        Retrieves a bearer (access) token using the refresh token grant type.
        Constructs the token endpoint URL based on the IAM host and tenant, then sends a POST request
        with the required parameters to obtain a new access token using the stored API key as a refresh token.
        Returns:
            str: The access token if the request is successful.
            None: If the request fails, prints the error and returns None.
        """

        if self.bearer_token is not None and datetime.now() < self.token_expiration:
            return self.bearer_token

        # Construct the URL for token retrieval
        url = f'{self.iam_host}/auth/realms/{self.tenant}/protocol/openid-connect/token'

        data = {  
            'grant_type': 'refresh_token',  
            'client_id': 'ast-app',  
            'refresh_token': f'{self.api_key}'
        }  

        # Send POST request to get the bearer token
        response = requests.post(url, data=data)  

        
        # If successful, return the access token
        if response.status_code == 200:  
            responseJson = response.json()
            expires_in = responseJson['expires_in']
            now = datetime.now()
            # 5 minute expiration buffer
            self.token_expiration = now + timedelta(seconds=expires_in - 300) 
            return response.json()['access_token'] 
        else:  
            # Print error if request failed
            logger.debug(f'Error: {response.status_code} - {response.text}')  
            return None

    def get_groups_dict(self):
        """
        Retrieve groups from the IAM server.
        
        Fetches a list of groups from the configured IAM host for the current tenant.
        Optionally filters the results by group name.
        
        Args:
            group_name (str, optional): The name of a specific group to retrieve. 
                                        If provided, only groups matching this name 
                                        will be returned. Defaults to None.
        
        Returns:
            list: A list of group dictionaries if the request is successful (status code 200).
                  Returns None if the request fails.
        """
        url = f'{self.iam_host}/auth/admin/realms/{self.tenant}/groups'
        headers = {
            'Authorization': f'Bearer {self.bearer_token}',
            'Content-Type': 'application/json'  
        }
        response = requests.get(url, headers=headers)
        groups_dict = {}
        if response.status_code == 200:
            groups = response.json()
            for group in groups:
                groups_dict[group['name']] = group['id']
        else:
            logger.debug(f'Error: {response.status_code} - {response.text}')
            
        return groups_dict

    def get_projects_dict(self):
        """
        Retrieves and prints a list of projects from the API.
        This method ensures a valid bearer token is available, constructs the appropriate API endpoint URL,
        and sends a GET request to retrieve a paginated list of projects. The response from the API is printed
        as plain text.
        Returns:
            None
        """
        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()

        # If there are more than 100 projects, page them using offset
        limit = 100
        offset = 0
        remaining = limit

        projects = []
        projects_dict = {}
        nProjectsInOrg = -1

        while remaining > 0:

            # Construct the URL for listing projects
            url = f'{self.ast_host}/api/projects?limit={limit}&offset={offset}'
            
            headers = {
                'Accept': 'application/json; version=1.0',
                'Authorization': f'Bearer {self.bearer_token}'
            }

            # Send GET request to list projects
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                jsonResp = response.json()
                nProjectsInOrg = nProjectsInOrg if nProjectsInOrg != -1 else jsonResp['filteredTotalCount']                
                projectsJson = jsonResp['projects']
                if projectsJson:
                    projects.extend(projectsJson)
                    for p in projectsJson:
                        projects_dict[p['name']] = p['id']
                remaining = nProjectsInOrg - len(projects)
                offset += limit
            else:                
                logger.debug(f'Could not fetch projects. Reason: ${response.reason}')
                break
            
        return projects_dict
        
    def create_application(self, application_name, description=None, criticality=3, rules=None, tags=None):
        """
        Creates a new application.
        Args:
            application_name (str): The name of the application.
            description (str): The description of the application.
            criticality (int): The criticality of the application.
            rules (array): The rules of the application.
            tags (dict): The tags of the application.
        Returns:
            str: The ID of the created application.
        """
        self.bearer_token = self.get_bearer_token()
        url = f'{self.ast_host}/api/applications'
        headers = {
            'Accept': 'application/json; version=1.0',
            'Authorization': f'Bearer {self.bearer_token}',
            'Content-Type': 'application/json; version=1.0'
        }
        data = {
            "name": application_name,
            "description": description,
            "criticality": criticality,
            "rules": rules if rules else [],
            "tags": tags if tags else {}
        }
        response = requests.post(url, headers=headers, data=json.dumps(data))
        if response.status_code == 201:
            jsonResp = response.json()
            application_id = jsonResp['id']
            logger.debug(f"Successfully created application {application_name} with ID {application_id}")
            return application_id
        else:
            logger.debug(f'Error creating application {application_name}: {response.status_code} - {response.text}')
            return None

    def is_authorized (self, application_id, group_id):
        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()
        url = f'{self.ast_host}/api/access-management?entity-id={group_id}&resource-id={application_id}'
        headers = {
            'Accept': 'application/json; version=1.0',
            'Authorization': f'Bearer {self.bearer_token}'
        }
        response = requests.get(url, headers=headers)
        # If authorized, response will be:
        # {
        #   "tenantID": "string",
        #   "entityID": "string",
        #   "entityType": "user",
        #   "entityName": "string",
        #   "entityRoles": [
        #     "string"
        #   ],
        #   "origin_entityID": "string",
        #   "resourceID": "string",
        #   "resourceType": "application",
        #   "resourceName": "string"
        # }
        rc = -1
        if response.status_code == 200:
            rc = 1
        elif response.status_code == 404:
            rc = 0
        return rc
        
    def authorize_application (self, application_id, group_id):
        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()
        url = f'{self.ast_host}/api/access-management'
        headers = {
            'Accept': 'application/json; version=1.0',
            'Authorization': f'Bearer {self.bearer_token}',
            'Content-Type': 'application/json; version=1.0'
        }
        
        data = {
            "entityID": group_id,
            "entityType": "group",
            "resourceType": "application",
            "resourceID": application_id
        }
        response = requests.post(url, headers=headers, data=json.dumps(data))
        rc = 0
        if response.status_code != 201:
            rc = 1
            logger.debug(f'Authorization Error Code: {response.status_code}, Message: {response.text}')
        return rc

    def get_group_id (self, group_name):
        group_id = self._group_cache.get(group_name, None)
        if group_id is not None: 
            return group_id        
        groups = self.get_groups()
        for group in groups.get('groups', []):
            if group['name'] == group_name:
                group_id = group['id']
                self._groups_cache[group_name] = group_id
                logger.debug(f'Group ID for group [{group_name}]: {group_id}')             
                break
        return group_id
        
    def get_application_id (self, application_name):        
        application_id = self._applications_cache.get(application_name, None)
        if application_id is not None: 
            return application_id        
        applications = self.get_applications_dict()
        for app in applications.get('applications', []):
            if app['name'] == application_name:
                application_id = app['id']
                self._applications_cache[application_name] = application_id
                logger.debug(f'Application ID for name [{application_name}]: {application_id}')             
                break
        return application_id

    def get_applications_dict(self):
        # curl --request GET \
        # --url https://ast.checkmarx.net/api/applications/ \
        # --header 'Accept: application/json; version=1.0' \
        """
        Retrieves the list of applications from the AST system.
        Returns:

            list: A list of applications if the request is successful.
            None: If the request fails, prints the error and returns None.
        """
        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()
        # Construct the URL and headers for application retrieval
        url = f'{self.ast_host}/api/applications/'
        headers = {  
            'accept': 'application/json; version=1.0',
            'Authorization': f'Bearer {self.bearer_token}'
        }
        # Send GET request to retrieve applications
        response = requests.get(url, headers=headers)
        applications_dict = {}
        # If successful, return the list of applications
        if response.status_code == 200:
           for app in response.json()['applications']:
                applications_dict[app['name']] = app['id']
        else:
            # Print error if request failed
            logger.debug(f'Error retrieving applications: {response.status_code} - {response.text}')

        return applications_dict

    def get_groups(self):
        # curl --request GET \
        #--url https://ast.checkmarx.net/api/access-management/groups \
        #--header 'Accept: application/json'
        # 
        # Query parameters:
        # limit: The maximum number of results to return (Default: 10)
        # 
        # offset: The number of pages to skip before starting to return results. The number of results per page is defined by the value of limit.
        """
        Retrieves the list of groups from the AST system.
        Returns:

            list: A list of groups if the request is successful.
            None: If the request fails, prints the error and returns None.  
        """
        limit = 10
        offset = 0
        all_groups = []
        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()
        while True:
            # Construct the URL and headers for group retrieval
            url = f'{self.ast_host}/api/access-management/groups?limit={limit}&offset={offset}'
            headers = {  
                'accept': 'application/json; version=1.0',
                'Authorization': f'Bearer {self.bearer_token}'
            }
            # Send GET request to retrieve groups
            response = requests.get(url, headers=headers)
            # If successful, process the list of groups
            if response.status_code == 200:
                response_json = response.json()
                groups = response_json
                all_groups.extend(groups)
                #print(all_groups)
                #exit(0)
                if len(groups) < limit:
                    break
                offset += limit
            else:
                # Print error if request failed
                logger.debug(f'Error retrieving groups: {response.status_code} - {response.text}')
                return None
        return all_groups
            
    def update_project_tags(self, project_id, tags_list):
        # curl --request PATCH \
        #   --url https://ast.checkmarx.net/api/projects/{id} \
        #   --header 'Accept: application/json; version=1.0' \
        #   --header 'Authorization: ' \
        #   --header 'Content-Type: application/json; version=1.0' \
        #   --header 'CorrelationId: ' \
        #   --data '{
        #   "name": "string",
        #   "repoUrl": "string",
        #   "mainBranch": "string",
        #   "criticality": 3,
        #   "tags": {
        #     "priority": "high"
        #   },
        #   "groups": [
        #     "string"
        #   ]
        # }'
        """
        Updates the tags for a specified project.
        Args:
            project_id (str): The ID of the project to update.
            tags_list (list): The list of tags to add to the project.
        Returns:
            bool: True if the update is successful, False otherwise.
        """
        # Ensure bearer token is available
        self.bearer_token = self.get_bearer_token()
        # Construct the URL and headers for project update
        url = f'{self.ast_host}/api/projects/{project_id}'
        headers = {  
            'accept': 'application/json; version=1.0',
            'Authorization': f'Bearer {self.bearer_token}',
            'Content-Type': 'application/json; version=1.0'
        }
        data = {   
            # tags is dictionary of string key and string value pairs. Use {key:""} format.
            "tags": {tag: "" for tag in tags_list}
        }
        # Print data
        logger.debug(f'Updating project [id:{project_id}] with tags: {data["tags"]}')

        # Send PATCH request to update the project's tags
        response = requests.patch(url, headers=headers, data=json.dumps(data))
        # If successful, return True
        if response.status_code == 204:
            logger.debug(f"Successfully updated tags for project {project_id}")
            return True
        else:
            # Print error if request failed
            logger.debug(f'Error updating tags for project {project_id}: {response.status_code} - {response.text}')
            return False    
        
   