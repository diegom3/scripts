import requests
import json
import os
import sys
import traceback
import sys
import os
import shutil
import subprocess
import hvac
import boto3
from .utils import print_message, print_command, print_error, print_success, print_debug, print_info,print_file_contents
from .utils import run_shell_command, safe_set_os_type_env, check_required_env_vars, checkout_repo
from .utils import set_vault_environment_variables_from_json, set_vault_secret_id

import json

def set_ami_users(input_file: str, output_file: str) -> None:
    """
    Reads the input JSON file, transforms the 'ami_users' field to a list if it's a string,
    and writes the transformed data to the output JSON file.

    Args:
        input_file (str): Path to the input JSON file.
        output_file (str): Path to the output JSON file where transformed data will be saved.
    """
    try:
        # Read the input JSON file
        with open(input_file, 'r') as f:
            data = json.load(f)

        # Transform 'ami_users' to a list if it's a string
        if isinstance(data.get('ami_users'), str):
            data['ami_users'] = [user.strip() for user in data['ami_users'].split(',')]

        # Write the transformed data to the output JSON file
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)

        print(f"Transformed input written to {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")



def fetch_config(args):
    # Try to load from file if provided and valid, otherwise try URL
     # Check if 'file' is an attribute of args and if it's provided
    config_file = getattr(args, 'file', None) or os.getenv('BIFROST_CONFIG_FILE')

    # Check if 'url' is provided
    config_url = getattr(args, 'url', None) or os.getenv('BIFROST_BRIDGE_CONFIG_URL')

    if not config_file and not config_url:
        # Neither file nor URL provided, raise an error
        raise ValueError("No configuration source provided. Please specify a --file or --url, or set the BIFROST_CONFIG_FILE environment variable.")

    if config_file:
        try:
            print_info(f"Attempting to load configuration from file: {config_file}") if args.debug else None
            with open(config_file, 'r') as file:
                config = json.load(file)
            if not isinstance(config, dict):
                print_error(f"Unexpected data type received from file: {type(config)}")
                traceback.print_exc()  # This prints the full stack trace
                raise TypeError(f"Expected config to be a dictionary, but got {type(config).__name__}")  # Re-raise the exception to propagate it upwards
            if args.debug:
                print_debug(f"Configuration loaded from file: {config}")
            set_environment_variables(args, config)
            return config
        except Exception as e:
            print_error(f"Error loading configuration from file: {e}")
            traceback.print_exc()  # This prints the full stack trace
            if not config_url:  # Exit if there is no URL to fallback to
                raise  # Re-raise the exception to propagate it upwards

    if config_url:
        try:
            print_info(f"Attempting to fetch configuration from URL: {config_url}") if args.debug else None
            if args.debug:
                print_debug("Running in debug mode: SSL verification is disabled.")
                response = requests.get(config_url, verify=False)
            else:
                print_info("Running in normal mode: SSL verification is enabled.")
                response = requests.get(config_url, verify=True)  # Assuming you have the proper certificate or trust store setup

            response.raise_for_status()  # Raises a HTTPError for bad responses
            config = response.json()
            if not isinstance(config, dict):
                print_error(f"Unexpected data type received from URL: {type(config)}")
                traceback.print_exc()  # This prints the full stack trace
                raise TypeError(f"Expected config to be a dictionary, but got {type(config).__name__}")  # Re-raise the exception to propagate it upwards
            if args.debug:
                print_debug(f"Configuration loaded from URL: {config}")
            set_environment_variables(args, config)
            return config
        except requests.exceptions.RequestException as e:
            print_error(f"Error fetching configuration from URL: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards

    # If no valid config source found, inform and exit
    print_info("No valid configuration source found. Exiting.", file=sys.stderr)   

def set_environment_variables(args, config, parent_key=''):
    """A utility function to set environment variables based on the bifrost config dictionary."""
    if not isinstance(config, dict):
        raise TypeError("Config must be a dictionary")

    for key, value in config.items():
        full_key = f"{parent_key}{key}".upper() if parent_key else key.upper()
        if isinstance(value, dict):
            set_environment_variables(args, value, f"{full_key}_")
        else:
            os.environ[full_key] = str(value)
            if args.debug:
                print_debug(f"Set environment variable: {full_key}={value}")

def fetch_account_config(args, account_id):
    """
    Fetches a Packer configuration JSON file from a specified URL based on the os_type,
    and writes it to a file in the specified directory.

    :param args: May include additional parameters such as the base URL for configuration files.
    :param os_type: The operating system type to fetch the config for (e.g., 'mac', 'windows').
    :param directory: The directory where the JSON file will be saved.
    """
    # Ensure no trailing slashes in base URL
    base_url = os.environ.get('PACKER_CONFIG_URL').rstrip('/')

    # Construct the URL to fetch the config JSON
    if args.debug:
        input_url = f"{os.environ.get('PACKER_CONFIG_URL')}/versions/{account_id}.json/?remoteBranch={os.environ.get('PACKER_DEBUG_TAG')}" 
    else:
        input_url = f"{os.environ.get('PACKER_CONFIG_URL')}/versions/{account_id}.json/"    

    
    try:
        # Make the HTTP GET request
        if args.debug:
            print_debug("Running in debug mode: SSL verification is disabled.")
            
            input_response = requests.get(input_url, verify=False)
        else:
            print_info("Running in normal mode: SSL verification is enabled.")
            
            input_response = requests.get(input_url, verify=True)  # Assuming you have the proper certificate or trust store setup
    
        
        if args.debug: 
            print_debug("input response is : {}".format(input_response.content))

        
        input_response.raise_for_status()  # Raises an HTTPError for bad responses (4XX, 5XX)
        # Load the JSON response content
        input_data = input_response.json()
        # Define the path for the output JSON file
        input_file_path = f"{args.build_directory}/input.json"

        with open(input_file_path, 'w') as f:
            json.dump(input_data, f, indent=4)

        print_info(f"Configuration for {os.environ.get('AMI_ACCOUNT')} saved to {input_file_path}")
        print_file_contents(input_file_path)

    except requests.exceptions.RequestException as e:
        print_error(f"Failed to fetch the configuration from {input_url}: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except json.JSONDecodeError:
        print_error(f"Failed to decode the JSON response. {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace 
        raise  # Re-raise the exception to propagate it upwards

def fetch_packer_config(args, os_type ):
    """
    Fetches a Packer configuration JSON file from a specified URL based on the os_type,
    and writes it to a file in the specified directory.

    :param args: May include additional parameters such as the base URL for configuration files.
    :param os_type: The operating system type to fetch the config for (e.g., 'mac', 'windows').
    :param directory: The directory where the JSON file will be saved.
    """
    # Ensure no trailing slashes in base URL
    base_url = os.environ.get('PACKER_CONFIG_URL').rstrip('/')

    # Construct the URL to fetch the config JSON
    if args.debug:
        config_url = f"{os.environ.get('PACKER_CONFIG_URL')}/versions/{os_type}_packer_config.json/?remoteBranch={os.environ.get('PACKER_DEBUG_TAG')}" 
    else:
        config_url = f"{os.environ.get('PACKER_CONFIG_URL')}/versions/{os_type}_packer_config.json/"

    print_info(f"Config url is: {config_url}")

    
    try:
        # Make the HTTP GET request
        if args.debug:
            print_debug("Running in debug mode: SSL verification is disabled.")
            response = requests.get(config_url, verify=False)
        else:
            print_info("Running in normal mode: SSL verification is enabled.")
            response = requests.get(config_url, verify=True)  # Assuming you have the proper certificate or trust store setup
    
        
        if args.debug: 
            print_debug("config response is : {}".format(response.content))

        response.raise_for_status()  # Raises an HTTPError for bad responses (4XX, 5XX)

        # Load the JSON response content
        config_data = response.json()
        # Define the path for the output JSON file
        output_file_path = f"{args.build_directory}/packer_config.json"

        # Write the JSON data to a file in the specified directory
        with open(output_file_path, 'w') as f:
            json.dump(config_data, f, indent=4)

        print_info(f"Configuration for {os_type} saved to {output_file_path}")
        print_file_contents(output_file_path)
        
        return print_success("Packer configs fetched!!!")

    except requests.exceptions.RequestException as e:
        print_error(f"Failed to fetch the configuration from {config_url}: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except json.JSONDecodeError:
        print_error(f"Failed to decode the JSON response. {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards  

def set_tfe_configs(args):
    env = os.environ

    if "azure" in env.get('LANDING_ZONE', '') or "azr" in env.get('LANDING_ZONE', ''):
        env['CLOUD'] = "azure"
        env['TF_CLI_CONFIG_FILE'] = f"{args.directory}/.terraform.tfrc"
        env['OAUTH_TOKEN_ID'] = "ot-gLwdZm1TKYtrNsnr"
    else:
        env['CLOUD'] = "aws"
        env['OAUTH_TOKEN_ID'] = "ot-97VFx8jMBBE8uC4g"
        # Define which AWS region to use
        target_directory = os.popen("find . -type d -name 'tfvars' -or -name 'environments' | head -1").read().strip()
        get_aws_region = os.popen(f"grep -ne 'region' {target_directory}/{env['TF_VARS']}.tfvars | grep -v 'destination_region' | awk '!/#/' | awk '{{print $3}}' | tr -d '\"' | cat").read().strip()
        if not get_aws_region:
            get_aws_region = os.popen(f"grep -ne 'us-west-2' {target_directory}/{env['TF_VARS']}.tfvars | grep -v 'destination_region' | awk '!/#/' | cat").read().strip()
            if not get_aws_region:
                env['AWS_DEFAULT_REGION'] = "us-east-1"  # Default
            else:
                env['AWS_DEFAULT_REGION'] = get_aws_region
        else:
            env['AWS_DEFAULT_REGION'] = get_aws_region

    check_required_env_vars(['TFE_HOST', 'TFE_AZURE_ORG', 'TFE_AWS_ORG', 'TF_WORKSPACE', 'LANDING_ZONE'])

    # Determine TFE_ORG based on LANDING_ZONE
    if env['CLOUD'] == "azure":
        env['TFE_ORG'] = os.getenv('TFE_AZURE_ORG', '')
    elif env['CLOUD'] == "aws":
        env['TFE_ORG'] = os.getenv('TFE_AWS_ORG', '')
    else:
        raise ValueError("Missing or invalid CLOUD environment variable")
    
    print_info(f"REPO_NAME {os.getenv('REPO_NAME')}")
    print_info(f"CLOUD {os.getenv('CLOUD')}")
    print_info(f"TFE_ORG {os.getenv('TFE_ORG')}")
    print_info(f"TF_CLI_CONFIG_FILE {os.getenv('TF_CLI_CONFIG_FILE')}")

    if env['CLOUD'] == "azure":
        print_message('creating terraformrc file')
        with open(f"{args.build_directory}/.terraform.tfrc", "w") as file:
            file.write(f"credentials \"{env['TFE_HOST']}\" {{\n")
            file.write(f"  token = \"{env['TOKEN']}\"\n")
            file.write("}\n")
        with open(f"{args.build_directory}/.terraform.tfrc", "r") as file:
            if args.debug:
                print_debug(file.read())
        print_success("Terraformrc created")
    return True

def ensure_tfenv_installed(args):
    work_dir = os.environ.get("WORKSPACE")
    tfenv_path = os.path.expanduser(f'{work_dir}/.tfenv/bin/tfenv')
    try:
        print_info(f"Checking {tfenv_path} --version")
        run_shell_command(f"{tfenv_path} --version")
    except Exception as e:
        print_info("tfenv is not installed, installing now...")
        run_shell_command(f"cp -r {work_dir}/bifrost-bridge/tfenv {work_dir}.tfenv ")


def set_terraform_version(args):
    terraform_version = os.getenv('TERRAFORM_VERSION')  # Default version if not set
    if terraform_version <= os.environ['TFE_LATEST_VERSION']:
        try:  
            print_info(f"Switching to {terraform_version}")
            ensure_tfenv_installed(args)
            print_info(f" Switch to the desired Terraform version using tfenv")
            run_shell_command(f"tfenv use {terraform_version}")
            print_info(f"Print the Terraform version to verify")
            run_shell_command(f"terraform --version")
        except Exception as e:
            print_error(f"Failed to switch Terraform version: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise 
    else:
        print_error(f"Terraform version support <= {os.environ['TFE_LATEST_VERSION']}")
        traceback.print_exc()  # This prints the full stack trace
        raise ValueError(f"Version {terraform_version} of terraform not supported!!")

def set_ami_config(args):
        run_shell_command('ls -la')
        run_shell_command('pwd')
        if args.command == "copy":
            path = args.config
        else: 
            path = args.directory
        jq_path = "/bin/jq"
        if args.debug: 
            #Install requirements and check directory status
            print_debug(f"Where am I? {os.getcwd()}")
       
        try:
            # Load JSON data from a file
            with open(f'{path}/ami_config.json', 'r') as file:
                ami_config = json.load(file)
        except FileNotFoundError as e :
            print_error(f"Error: The file 'ami_config.json' does not exist. {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards
        except json.JSONDecodeError as e:
            print_error(f"Error: JSON decode error in 'ami_config.json'. : {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards

        # Get the OS type from environment or use default from JSON
        ami_os_type = ami_config[0].get('os_type') if 'AMI_OS_TYPE' not in os.environ else os.environ['AMI_OS_TYPE']
        print_info(f"AMI_OS_TYPE = {ami_os_type}")
        print_info("Set environment variable for AMI_OS_TYPE")
        os.environ["AMI_OS_TYPE"]=ami_os_type

        if args.debug: 
            print_debug(f"Current ami_config.json is {ami_config}")

        try:

            print_info("Setting configs from ami_config.json")
            # Set environment variables based on ami_os_type
            safe_set_os_type_env('ApplicationID', ami_config, ami_os_type,  'SYSID_APP')
            safe_set_os_type_env('AMI_Account_Name', ami_config, ami_os_type,'AMI_ACCOUNT')
            safe_set_os_type_env('KMS_Key',ami_config, ami_os_type, 'KMS_KEY')
            safe_set_os_type_env('Alt_KMS_Key', ami_config, ami_os_type,'ALT_KMS_KEY')  
            safe_set_os_type_env('description', ami_config, ami_os_type, 'AMI_DESCRIPTION')
            safe_set_os_type_env('Name', ami_config, ami_os_type, 'NAME_TAG')
            safe_set_os_type_env('instancetype', ami_config, ami_os_type, 'INSTANCE_TYPE')
            safe_set_os_type_env('Requester', ami_config, ami_os_type, 'REQUESTER')
            safe_set_os_type_env('Environment', ami_config, ami_os_type, 'ENVIRONMENT')
            safe_set_os_type_env('Support', ami_config, ami_os_type, 'SUPPORT')
            safe_set_os_type_env('Schedule', ami_config, ami_os_type, 'SCHEDULE')
            safe_set_os_type_env('assignmentgroup', ami_config, ami_os_type, 'ASSIGNMENT_GROUP')
            safe_set_os_type_env('playbook', ami_config, ami_os_type, 'PLAYBOOK')
            safe_set_os_type_env('ansible_run_tags', ami_config, ami_os_type, 'ANSIBLE_RUN_TAGS')
            safe_set_os_type_env('ansible_skip_tags', ami_config, ami_os_type, 'ANSIBLE_SKIP_TAGS')
            safe_set_os_type_env('ApplicationID', ami_config, ami_os_type, 'SYSID')
        except Exception as e:
            print_error(f"Error setting configs: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards

            # Environment setup from os_json
        
def convert_env_name(base_name, source):
    """
    Converts a base environment name to a specific format depending on the source.

    Args:
    base_name (str): The base environment name (e.g., 'cfg-consumer-dev').
    source (str): The source environment ('qa', 'p-1', 'prod', or 'p').

    Returns:
    str: The modified environment name based on the source.
    """
    print_info(f"Converting {base_name} to {source}")
    if source in ['qa', 'p-1']:
        # Replace 'dev' with 'p-1' if the source is 'qa' or 'p-1'
        return base_name.replace('dev', 'p-1')
    elif source in ['prod', 'p']:
        # Replace 'dev' with 'p' if the source is 'prod' or 'p'
        return base_name.replace('dev', 'p')
    else:
        # Return the base name if the source does not match any expected values
        print_info(f"Converted to  {base_name}")
        return base_name
    
def set_aws_creds(args, source):
    set_ami_config(args)
    os.environ['AMI_ACCOUNT'] = convert_env_name(os.environ['AMI_ACCOUNT'], source)
    #fetch_account_config(args, os.environ.get('AMI_ACCOUNT'))
    if args.debug:
        print_info("where am I? ")
        run_shell_command("ls -la")
        run_shell_command("pwd")
    set_vault_environment_variables_from_json(f'{args.build_directory}/input.json')
        # Additional setup for fetching secrets as before
    vault_url = os.getenv('VAULT_ADDR')  
    role_id = os.getenv('VAULT_ROLE_ID')
    aws_role = os.getenv('VAULT_ROLE')
    namespace = os.getenv('VAULT_NAMESPACE').upper()
    set_vault_secret_id(args, source)
    secret_id = os.getenv('VAULT_SECRET_ID')


    #Will need to update for prod.
    #ca_cert = '/Users/d122053/certs/curl-ca-bundle.pem'

    # Namespace and AWS role setup
    if args.debug: 
        print_debug(f"Vault URL: {vault_url}")
        print_debug(f"Role ID: {role_id}")
        print_debug(f"Secret ID: {secret_id}")
        print_debug(f"Namespace: {namespace}")
    
    try:
        client = hvac.Client(url=vault_url, namespace=namespace, timeout=60, verify=False)
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    except hvac.exceptions.InvalidRequest as e:
        print_error(f"Login failed: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except hvac.exceptions.VaultDown as e:
        print_error(f"Vault is not reachable: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    
    

    # Fetch AWS credentials using AWS Secrets Engine
    try:

        aws_creds = client.secrets.aws.generate_credentials(name=aws_role, ttl=3600)
        aws_credentials = aws_creds['data']
        print_info(f"Generated AWS credentials for role {aws_role}: {aws_credentials}")
        print_info(f"Access Key: {aws_credentials['access_key']}")
        print_info(f"Type of Access Key: {type(aws_credentials['access_key'])}")
        # Set environment variables for the AWS credentials
        os.environ['AWS_ACCESS_KEY_ID'] = aws_credentials['access_key']
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_credentials['secret_key']
        os.environ['AWS_SESSION_TOKEN'] = aws_credentials.get('security_token', '')

        if args.debug:
            # Optional: Use boto3 to verify credentials
            session = boto3.Session(
                aws_access_key_id=aws_credentials['access_key'],
                aws_secret_access_key=aws_credentials['secret_key'],
                aws_session_token=aws_credentials.get('security_token', None)
            )
            sts_client = session.client('sts')
            caller_identity = sts_client.get_caller_identity()
            print_info(f"Caller Identity for verification: {caller_identity}")
    except Exception as e:
        print_error(f"Error generating AWS credentials from Vault: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
