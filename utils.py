import hashlib
import os 
import sys
import boto3
import subprocess
import hvac
import fnmatch
import json 
import base64
import traceback
import shutil
import glob
from datetime import datetime, timedelta
import os
import traceback


# Define ANSI color codes
ANSI_NONCOLOR = "\033[0m"
MESSAGE_COLOR = "\033[1;34m ##[section]" + ANSI_NONCOLOR
COMMAND_COLOR = "\033[1;33m ##[command]" + ANSI_NONCOLOR
ERROR_COLOR = "\u001b[31;1m ##[error]" + ANSI_NONCOLOR
SUCCESS_COLOR = "\033[32m ##[success]" + ANSI_NONCOLOR
DEBUG_COLOR = "\u001b[35;1m ##[debug]" + ANSI_NONCOLOR
INFO_COLOR = "\033[1;33m ##[INFO]" + ANSI_NONCOLOR
FILE_COLOR = "\033[1;34m ##[FILE]" + ANSI_NONCOLOR

# Define functions to print messages in different colors
def print_message(text):
    print(f"{MESSAGE_COLOR} {text}")

def check_required_env_vars(required_vars):
    if 'TERRAFORM_DESTROY' in required_vars:
        value = os.getenv('TERRAFORM_DESTROY')
        if not value:
            os.environ['TERRAFORM_DESTROY'] = 'FALSE'
            print_debug("Environment variable TERRAFORM_DESTROY was not provided, setting to false.")
        else:
            print_debug(f"Environment variable TERRAFORM_DESTROY is set to {value}")
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            print_debug(f"Environment variable {var} is missing.")
            raise ValueError(f"Missing required environment variable: {var}")
        print_debug(f"Environment variable {var} is set to {value}")

def print_command(text):
    print(f"{COMMAND_COLOR} {text}")

def print_error(text):
    print(f"{ERROR_COLOR} {text}")

def print_success(text):
    print(f"{SUCCESS_COLOR} {text}")

def print_debug(text):
    print(f"{DEBUG_COLOR} {text}")

def print_info(text):
    print(f"{INFO_COLOR} {text}")

def print_file(text):
    print(f"{FILE_COLOR} {text}")

def file_exists(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Config file not found: {filepath}")
    return os.path.isfile(filepath)

def generate_code_hash(args, exclude_dirs=None, ignore_files=None):
    """
    Generate a hash by walking through the files in the specified directory,
    excluding specified directories and ignoring specific files that match patterns.
    
    :param args: Namespace with directory attribute indicating where to start hashing.
    :param exclude_dirs: List of directory patterns to exclude from hashing.
    :param ignore_files: List of file patterns to ignore from hashing.
    """

    sha1 = hashlib.sha1()

    if args.debug: 
        print_debug("Current directory content")
        run_shell_command(f"ls -la {args.directory}")
        print_debug(f"Excluding files {ignore_files} and directories {exclude_dirs}")
    
    for root, dirs, files in os.walk(args.directory):
        if exclude_dirs:
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pat) for pat in exclude_dirs)]
        
        for file in files:
            if ignore_files and any(fnmatch.fnmatch(file, pat) for pat in ignore_files):
                continue  # Skip ignored files

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:  # Ensure binary mode
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        sha1.update(chunk)  # chunk should be bytes
            except IOError as e:
                print_info(f"Unable to read file {file_path}. Error: {e}")

    return sha1.hexdigest()

def ami_exists_with_tag(args, unique_hash):
    """
    Check if an AMI exists with a matching 'Code Hash' tag value and return its details if it does.
    
    :param unique_hash: The hash value to check against existing AMIs.
    :return: A tuple (exists: bool, ami_details: dict)
    """
    try:
        ec2 = boto3.client('ec2')
        sts = boto3.client('sts')
        
        # Get the account ID
        account_id = sts.get_caller_identity().get('Account')
        
        if args.debug: 
            print_debug(f"Checking image with Code Hash : {unique_hash}")
            print_debug(f"Current AWS Account ID: {account_id}")
        
        response = ec2.describe_images(
            Filters=[
                {'Name': 'tag:Code Hash', 'Values': [unique_hash]},
                {'Name': 'state', 'Values': ['available']}  # Consider only available AMIs
            ]
        )

        images = response.get('Images', [])
        print_info(f"Found images : {images}")
        exists = len(images) > 0
        ami_details = images[0] if exists else {}
        if exists: 
            if args.debug:
                print_debug(f"Current ami to json details {ami_details}")
            with open(f'{args.build_directory}/source_ami_id.txt', 'w') as file:
                json.dump(ami_details, file, indent=4)
            print_info(f"AMI ID details written to file.")
        else: 
            print_info(f"No ami found for hash {unique_hash}")
    
        return exists, ami_details
    except Exception as e:
        print_error(f"An error occurred checking hash in aws: {e}") 
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
        
def get_latest_golden_ami(args, ami_details, ami_os_version_filter):

    # Assume the ami_os_version_filter ends with '*' and replace it with the desired suffix "-BASE-BUILD"

    print_info(f"Original AMI OS version filter: {ami_os_version_filter}")

    # Initialize the EC2 client
    ec2_client = boto3.client('ec2')

    # Define filters to identify your golden images
    filters = [
        {'Name': 'name', 'Values': [ami_os_version_filter]}
    ]
    owners=[
        '793022030544'
    ]

    # Query the AMIs based on the filters
    response = ec2_client.describe_images(Filters=filters,Owners=owners)
    if args.debug:
        print_debug(f" reponse from aws {response}")

    # Extract the relevant information from the response
    golden_images = response['Images']

    # Calculate creation date range (e.g., within the last 90 days)
    creation_date_range = datetime.utcnow() - timedelta(days=90)

    # Filter images based on creation date
    filtered_images = []
    print_info("Filter images")
    for image in golden_images:
        # Check if the creation date is within the specified range
        creation_date = datetime.strptime(image['CreationDate'], "%Y-%m-%dT%H:%M:%S.%fZ")
        if args.debug:
            print_info(f"Creations data {creation_date}")
            print_info(f"Creation data range : {creation_date_range}")
        if creation_date >= creation_date_range:
            filtered_images.append(image)

    # Sort the filtered images by creation date in descending order
    sorted_images = sorted(filtered_images, key=lambda x: x['CreationDate'], reverse=True)

    if not sorted_images:
        print_error("No AMI images found matching the filter criteria.")
        return None  # Or handle as needed

    # Return the ami details of the latest image
    return sorted_images[0]

def compare_latest_golden_ami(args, ami_details, golden_ami_details):
    try: 
        print_info("First get creation date from ami details")
        ami_creation_date_str = ami_details.get('CreationDate', '')
        ami_creation_date = datetime.fromisoformat(ami_creation_date_str.replace('Z', '+00:00'))
        print_success(f"AMI created {ami_creation_date_str}")

        print_info("Get golden ami creation date")
        golden_ami_creation_date_str = golden_ami_details.get('CreationDate', '')
        golden_ami_creation_date = datetime.fromisoformat(golden_ami_creation_date_str.replace('Z', '+00:00'))
        print_success(f"Golden AMI created {golden_ami_creation_date_str}")

        # Comparing the two datetime objects
        if ami_creation_date > golden_ami_creation_date:
            print_info("The AMI is newer than the Golden AMI.")
            return False
        elif ami_creation_date < golden_ami_creation_date:
            print_info("The AMI is older than the Golden AMI.")
            return True
        else:
            print_info("The AMI and the Golden AMI were created at the same time.")
    
    except Exception as e:
        print_error(f"Was not able to compare ami to golden ami creation times: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def fetch_vault_secrets(args, ami_account):   

    vault_url = os.getenv('VAULT_ADDR')  
    role_id = os.getenv('VAULT_ROLE_ID')
    secret_id = os.getenv('VAULT_SECRET_ID')
    aws_role = os.getenv('VAULT_ROLE')
    namespace = os.getenv('VAULT_NAMESPACE').upper()

    #Will need to update for prod.
    #ca_cert = '/Users/d122053/certs/curl-ca-bundle.pem'

    # Namespace and AWS role setup
    if args.debug: 
        print_debug(f"Vault URL: {vault_url}")
        print_debug(f"Role ID: {role_id}")
        print_debug(f"Secret ID: XXXXXXXXX")
        print_debug(f"Namespace: {namespace}")
    
    try:
        client = hvac.Client(url=vault_url, namespace=namespace, timeout=60, verify=False)
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    
        print_info("Fetching KeyPair from Vault")
        if args.debug: 
            print_debug(f"client is {client}\n")
            print_debug(f"Client details: {vars(client)}\n")
            print_debug(f"Client attributes: {dir(client)}\n")
            print_debug(f"Is authenticated: {client.is_authenticated()}\n")

        # Use the HVAC client to get the key pair data
        print_info("clinet token : {}".format(client.token))
        os.environ['VAULT_TOKEN'] = client.token
        
        if args.debug:
            os.environ['VAULT_SKIP_VERIFY'] = "true" 

        # Fetch the private key data

    
        key_data_json = run_shell_command(f"vault kv get -format=json secrets/cfg-aws-cldsvcs-devops/IIDKPackerKeyPairs/{ami_account}")
        key_data = json.loads(key_data_json)
        private_key = key_data['data']['data'].values()  # This line might need adjustment based on actual JSON structure

        packer_kp_file_path = f"{args.build_directory}/packer-kp.pem"
        # Write the private key to a file and set permissions
        with open(packer_kp_file_path, 'w') as key_file:
            key_file.write(next(iter(private_key)))  # Assuming there's at least one key
        print_info("Set 600 permissions on packer-kp.pem")
        os.chmod(packer_kp_file_path, 0o600)

        if args.debug:
            print_debug("Did the pem key get written locally??")
            print_debug("KeyPair fetched and saved as packer-kp.pem")
            run_shell_command("ls -la")
            run_shell_command("pwd")

    except hvac.exceptions.VaultError as e:
        print_error(f"Vault error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards 
    return 

def check_snow(args, sysid_app):
    """
    Check ServiceNow for business app data, create a JSON file from the response,
    and handle business mapping.

    :param args: may include other necessary command-line arguments
    :param sysid_app: SYSID used in the API request
    """
    api_password_encoded = base64.b64encode(f'cmdb.integration:{os.getenv("SNOW_API_PASSWORD")}'.encode()).decode()

    try:
        # Execute the curl command and capture the output
        print_info("Checking servive now!!!!")
        if args.debug: 
            print_debug("SYSID : {}".format(sysid_app))
            print_debug("SNOW PAASWORD : {}".format(api_password_encoded))
        curl_command = (
            f'curl -s "https://wwwservicenow.production.citizensbank.myshn.net/api/icfg/servicenowbusinessappdata/get_business_app_data/{sysid_app}" '
            f'--request GET --header "Accept:application/json" --header "Authorization: Basic {api_password_encoded}"'
        )
        snow_response = subprocess.getoutput(curl_command)

        # Attempt to parse JSON data
        snow_data = json.loads(snow_response)

        if args.debug: 
            print_debug("SNOW PAYLOAD: {}".format(snow_data))

        # Create the tags.auto.pkrvars.json file
        with open(f"{args.build_directory}/tags.auto.pkrvars.json", "w") as file:
            json.dump(snow_data.get("result", {}), file, indent=4)

        # Load data back from the file to simulate reading from tags.auto.pkrvars.json
        with open(f"{args.build_directory}/tags.auto.pkrvars.json", "r") as file:
            business_data = json.load(file)

        print_info("Service Now payload is : {}".format(business_data))

        # Extract and export business mapping if available
        if business_data and "Business Application Tag" in business_data:
            business_mapping = business_data["Business Application Tag"].lower()
            os.environ['BUSINESSMAPPING'] = business_mapping
            print_info(f"Business Mapping: {business_mapping}")
            return business_mapping
        else:
            print_info("No business mapping found or empty response.")
            raise KeyError("No business mapping found or empty response.")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def print_file_contents(file_path):
    """
    Print the contents of the specified file similar to the 'cat' command in bash.

    :param file_path: Path to the file to be printed.
    """
    try:
        with open(file_path, 'r') as file:
            contents = file.read()  # Read the entire content of the file
            print_file(contents)  # Print the contents to the console
    except FileNotFoundError as e:
        print_error(f"No file found at {file_path}. Please check the file path. : {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An error occurred while reading the file: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def run_shell_command(command, directory=None,args=None):
    if directory is None:
        directory = os.getcwd()

    env = os.environ.copy()
    print_info(f"Will execute command: {command} in directory: {directory}")

    if command.startswith("terraform") or command.startswith("tfenv"):
    # Set up the environment
        print_info("Setting path for terraform or tfenv call.")
        env['PATH'] = f"{os.path.expanduser(os.getenv('WORKSPACE') + '.tfenv/bin')}:{env['PATH']}"
        print_info(f"PATH is : ${env['PATH']}")
        print_info(f"What is available in bin? ")
        run_shell_command(f" ls -la {os.path.expanduser(os.getenv('WORKSPACE') + '.tfenv/bin')}")

    

    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=directory,
            universal_newlines=True
        )
        
        # Log the command's stdout and stderr
        print_info(result.stdout)
        if result.stderr:
            print_error(result.stderr)

        # Raise an error only if the exit code is non-zero
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command)
        
        return result.stdout
    except subprocess.CalledProcessError as e:
        print_error(f"Command '{command}' failed with return code {e.returncode}")
        traceback.print_exc()
        raise
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        raise
    
def checkout_repo(args, repo_url, branch_name, target_dir):
    try:
        # Create the target directory
        os.makedirs(target_dir, exist_ok=True)

        print_info(f"Cloning repository from {repo_url} into {target_dir}")
        subprocess.run(['git', 'clone', repo_url, target_dir], check=True)
        print_info("Repository cloned successfully.")
        
        if branch_name:
            # Checkout the specified tag
            print_info(f"Checking out tag {branch_name}")
            subprocess.run(['git', 'checkout', branch_name], cwd=target_dir, check=True)
            print_info(f"Checked out to {branch_name} successfully.")
        
        # Execute the git clone command
        print_success("Repository successfully cloned.")
        
    except subprocess.CalledProcessError as e:
        print_error(f"An error occurred while trying to clone the repository: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def copy_files(src_pattern, dst):
    try:
        # Create the destination directory if it doesn't exist
        if not os.path.exists(dst):
            os.makedirs(dst)
            print_message(f"Created destination directory {dst}")

        for src in glob.glob(src_pattern):
            if os.path.isfile(src):
                print_message(f"Copying file {src} to {dst}")
                shutil.copy(src, dst)
            elif os.path.isdir(src):
                print_message(f"Copying directory {src} to {dst}")
                shutil.copytree(src, os.path.join(dst, os.path.basename(src)))
    except Exception as e:
        print_error(f"An unexpected error occurred trying to copy file: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def set_os_environment_variables_from_json(json_data_path, os_type_name):
    """
    Sets multiple environment variables based on the attributes of a JSON object that matches a specific os_type_name.
    :param json_data_path: Path to the JSON file to parse.
    :param os_type_name: The os_type_name to match against the 'name' field in the JSON objects.
    """
    if not isinstance(json_data_path, str):
        raise TypeError(f"json_data_path must be a string, got {type(json_data_path).__name__} instead.")

    try:
        with open(json_data_path, 'r') as file:
            data = json.load(file)

        config_block = next((item for item in data if item.get('name') == os_type_name), None)

        if config_block:
            for key in ['owner', 'bootdisk', 'aminame', 'amiosversionfilter']:
                env_var_name = f"AMI_{key.upper()}" 
                if key in config_block:
                    os.environ[env_var_name] = config_block[key]
                    print_info(f"Set {env_var_name} = {config_block[key]}")
                else:
                    print_info(f"No '{key}' key found in the configuration for {os_type_name}")
                    raise ValueError("No '{key}' key found in the configuration for {os_type_name}".format(key=key, os_type_name=os_type_name))
        else:
            print_info(f"No configuration found for os_type_name '{os_type_name}'")
            raise ValueError("No configuration found for os_type_name '{os_type_name}'".format(os_type_name=os_type_name))

    except FileNotFoundError as e:
        print_error(f"Error: The file {json_data_path} does not exist. : {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except json.JSONDecodeError:
        print_error(f"Error: Could not decode JSON. : {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def set_vault_environment_variables_from_json(json_data_path):
    """
    Sets multiple environment variables based on the attributes of a JSON object that matches a specific os_type_name.
    :param json_data_path: Path to the JSON file to parse.
    :param os_type_name: The os_type_name to match against the 'name' field in the JSON objects.
    """
    if not isinstance(json_data_path, str):
        raise TypeError(f"json_data_path must be a string, got {type(json_data_path).__name__} instead.")

    try:
        with open(json_data_path, 'r') as file:
            data = json.load(file)

        if data:
            for key in ['role', 'role_id', 'namespace']:
                env_var_name = f"VAULT_{key.upper()}" 
                if key in data:
                    os.environ[env_var_name] = data[key]
                    print_info(f"Set {env_var_name} = {data[key]}")
                else:
                    print_info(f"No '{key}' key found in the configuration for vault")
                    raise ValueError("No '{key}' key found in the configuration for vault")
        else:
            print_info(f"No configuration found for os_type_name vault'")
            raise ValueError("No configuration found for os_type_name vault")

    except FileNotFoundError as e:
        print_error(f"Error: The file {json_data_path} does not exist. : {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except json.JSONDecodeError as e:
        print_error(f"Error: Could not decode JSON. : {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def safe_set_os_type_env(key, data, os_type, env_var_name):
    """Safely set environment variables only if the key exists in the item and matches the os_type."""
    try:
        # Attempt to find the first item that matches both the os_type and contains the key
        value = next((item.get(key) for item in data if item.get('os_type') == os_type and item.get(key) is not None), None)
        if value is not None:  # Only set the environment variable if a value was found
            os.environ[env_var_name] = value
            print_info(f"Set {env_var_name} = {value}")  # Debugging output
        else:
            print_info(f"Did not set {env_var_name} as no matching {key} was found for os_type {os_type}")
    except Exception as e:
        print_error(f"Error in setting {env_var_name}: {e}")
        print_error(f"Data inspected: {[item for item in data if item.get('os_type') == os_type]}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def load_config_file(file_path):
    """
    Reads a *.config file with KEY=VALUE pairs and sets them as environment variables.
    Raises an error if any key is not uppercase.
    
    :param file_path: Path to the config file
    :type file_path: str
    """

    if file_exists(file_path): 
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):  # Ignore empty lines and comments
                    if '=' not in line:
                        raise ValueError(f"Invalid line in config file: {line}")
                    
                    key, value = line.split('=', 1)
                    key, value = key.strip(), value.strip()

                    if not key.isupper():
                        raise ValueError(f"Key is not uppercase: {key}")
                    
                    os.environ[key] = value
                    print_info(f"Set environment variable: {key}={value}")


def find_tfvars_file(environment, args):
    """Find the appropriate .tfvars file in the tfvars directory for the given environment."""
    tfvars_files = glob.glob(f"{args.directory}/tfvars/{environment}-*.tfvars")
    if not tfvars_files:
        raise FileNotFoundError(f"No tfvars file found for environment: {environment}")
    print_message(f"Files : {tfvars_files}")
    print_message("Setting the TF_VARS")
    os.environ['TF_VARS'] = os.path.basename(tfvars_files[0]).replace('.tfvars', '')
    print_info(f"TFVARS : {os.environ['TF_VARS']}")
    return os.path.basename(tfvars_files[0]).replace('.tfvars', ''), tfvars_files

def set_vault_secret_id(args, env):
    """
    Sets the VAULT_SECRET_ID environment variable based on the provided environment.

    Args:
    env (str): The environment ('dev', 'qa', 'prod') which corresponds to different Vault secret IDs.

    Raises:
    KeyError: If the corresponding environment variable is not found.
    """
    # Mapping environments to their corresponding environment variable names
    env_mapping = {
        'dev': 'VAULT_SECRET_ID_P2',  # For development environment
        'qa': 'VAULT_SECRET_ID_P1',   # For QA environment
        'prod': 'VAULT_SECRET_ID_P'   # For production environment
    }

    # Get the appropriate environment variable name from the mapping
    if env in env_mapping:
        if args.debug: 
            print_debug(f"Looks like we are setting {env}")
        vault_env_var = env_mapping[env]
        vault_secret_id = os.getenv(vault_env_var)

        # Check if the environment variable is actually set in the system
        if vault_secret_id is None:
            raise KeyError(f"The environment variable {vault_env_var} is not set.")

        # Set the VAULT_SECRET_ID environment variable to the fetched value
        os.environ['VAULT_SECRET_ID'] = vault_secret_id
        print(f"VAULT_SECRET_ID has been set to the value of {vault_env_var}: {vault_secret_id}")
    else:
        raise ValueError(f"Invalid environment specified: {env}. Choose from 'dev', 'qa', or 'prod'.")

