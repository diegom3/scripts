import sys
import traceback
import sys
import subprocess
import requests
import os
import glob
import hvac
import json
import shutil
import re
from .config import set_terraform_version, fetch_account_config
from .utils import print_command, print_debug, print_error, print_file_contents
from .utils import set_vault_environment_variables_from_json,find_tfvars_file
from .utils import print_info, print_message, print_success, run_shell_command, set_vault_secret_id

###########################################################################################
###########################  AZURE FUNCTIONS ####################################################
###########################################################################################

def create_tf_rc(args, host, token):
    os.environ['TF_CLI_CONFIG_FILE']=f"{os.getcwd()}/.terraform.tfrc"
    os.environ['TFENV_NETRC_PATH']=f"{os.getcwd()}/.terraform.tfrc"
    print_info(f"TF CLI PATH : {os.getenv('TFENV_NETRC_PATH')}")
    run_shell_command(f"rm -rf .terraform.tfrc")
    run_shell_command(f"touch .terraform.tfrc")
    terraform_rc= f""" 
    credentials "{os.getenv('TFE_HOST')}" {{
  token = "{os.getenv('TFE_TOKEN')}"
}}
"""
    
    with open(f'.terraform.tfrc', 'a+') as file:
        file.write(terraform_rc)
    
    print_command(f" Terraform rc created") 
    print_success(f"Finishing to create provider.tf for providers configuration")
    

def create_azure_provider(args):
    print_message(f"Creating provider.tf for backend configuration")
    
    provider_config = """
provider "azurerm" {
  features {}
  client_id       = var.client_id
  client_secret   = var.client_secret
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}

provider "datadog" {
  api_key = var.datadog_api_key
  app_key = var.datadog_app_key
}
"""
    with open(f'{args.directory}/spw/provider.tf', 'w') as file:
        file.write(provider_config)
    
    print_command(f" Terraform fmt on provider.tf")
    if args.debug:
        print_debug(f"cat provider.tf")
        run_shell_command(f"cat {args.directory}/spw/provider.tf")
    with open(f'{args.directory}/spw/provider.tf', 'r') as file:
        print(file.read())
    
    print_success(f"Finishing to create provider.tf for providers configuration")

def create_azure_backend(args):
    print_message(f"Creating backend.tf for backend configuration")
    
    backend_config = """
terraform {
  required_version = ">=0.15.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.18.0"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = "3.36.0"
    }
  }

  cloud {
    hostname     = "$TFE_HOST"
    organization = "$TFE_ORG"
 
    workspaces {
      name = "$TF_WORKSPACE"
    }
  }
}
"""
    with open(f'{args.directory}/spw/backend.tf', 'w') as file:
        file.write(backend_config)
    
    print_command(f"cat backend.tf")
    run_shell_command(f"cat {args.directory}/spw/backend.tf")
    with open(f'{args.directory}/spw/backend.tf', 'r') as file:
        print(file.read())
    
    print_success(f"Finishing to create backend.tf for backend configuration")

def create_azure_provider_variables(args):
    print_message(f"Creating provider_variables.tf for backend configuration")
    
    variables_config = """
variable "client_id" {
 description = "Azure Client ID"
 type        = string
 default     = null
}

variable "client_secret" {
  description = "Azure Client secret"
  type        = string
  default     = null
}

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  default     = null
}

variable "tenant_id" {
  description = "Azure Tenant ID"
  type        = string
  default     = null
}
"""
    with open(f'{args.directory}/spw/provider_variables.tf', 'w') as file:
        file.write(variables_config)
    
    print_command(f"cat provider_variables.tf")
    run_shell_command(f"cat {args.directory}/spw/provider_variables.tf")
    with open(f'{args.directory}/spw/provider_variables.tf', 'r') as file:
        print(file.read())
    
    print_success(f"Finishing to create provider_variables.tf for backend configuration")


###########################################################################################
###########################################################################################
###########################################################################################
    


###########################################################################################
###########################  AWS FUNCTIONS ####################################################
###########################################################################################


def create_aws_provider(args):
    workspace_name = os.getenv('TF_WORKSPACE')
    version = "~> 5.0"
    ttl = "7200" if "db-workload" in workspace_name else "60m"
    
    custom_endpoints = ""
    endpoint_flag = False
    with open(f"{args.directory}/tfvars/{os.getenv('TF_VARS',)}.tfvars", 'r') as file:
        for line in file:
            if "endpoints" in line:
                endpoint_flag = True
                continue
            if endpoint_flag:
                if "}" in line:
                    break
                custom_endpoints += line

    provider_tf_content = f"""data "terraform_remote_state" "vault_creds" {{
    backend = "remote"
    config = {{
        organization = "{os.getenv('TFE_ORG')}"
        hostname = "{os.getenv('TFE_HOST')}"
        workspaces = {{
            name = var.vault_creds_workspace
        }}
    }}
}}

provider "vault" {{
    address = var.vault_address
    auth_login {{
        path = "auth/approle/login"
        namespace = data.terraform_remote_state.vault_creds.outputs.service_namespace
        parameters = {{
            role_id = data.terraform_remote_state.vault_creds.outputs.approle_roles["terraform"].role_id
            secret_id = data.terraform_remote_state.vault_creds.outputs.approle_roles["terraform"].secret_id
        }}
    }}
}}

data "vault_aws_access_credentials" "creds" {{
    backend = data.terraform_remote_state.vault_creds.outputs.aws_secrets_path
    role = var.vault_role_name
    type = "sts"
    ttl = "{ttl}"
}}

provider "aws" {{
    region = var.region
    access_key = data.vault_aws_access_credentials.creds.access_key
    secret_key = data.vault_aws_access_credentials.creds.secret_key
    token = data.vault_aws_access_credentials.creds.security_token
    endpoints {{
        s3                = var.region == "us-east-1" ? var.s3_ue1_interface_endpoint : var.region == "us-east-2" ? var.s3_ue2_interface_endpoint : var.region == "us-west-2" ? var.s3_uw2_interface_endpoint : null
        glue              = var.region == "us-east-1" ? var.glue_ue1_interface_endpoint : null
        logs              = var.region == "us-east-1" ? var.logs_ue1_interface_endpoint : var.region == "us-east-2" ? var.logs_ue2_interface_endpoint : var.region == "us-west-2" ? var.logs_uw2_interface_endpoint : null
        sqs               = var.region == "us-east-1" ? var.sqs_ue1_interface_endpoint : null
        cloudwatchevents  = var.region == "us-east-1" ? var.events_ue1_interface_endpoint : null
        stepfunctions     = var.region == "us-east-1" ? var.step_function_ue1_interface_endpoint : var.region == "us-east-2" ? var.step_function_ue2_interface_endpoint : var.region == "us-west-2" ? var.step_function_uw2_interface_endpoint : null
        kinesis           = var.region == "us-east-1" ? var.kinesis_ue1_interface_endpoint : var.region == "us-east-2" ? var.kinesis_ue2_interface_endpoint : var.region == "us-west-2" ? var.kinesis_uw2_interface_endpoint : null
        athena            = var.region == "us-east-1" ? var.athena_ue1_interface_endpoint : var.region == "us-east-2" ? var.athena_ue2_interface_endpoint : var.region == "us-west-2" ? var.athena_uw2_interface_endpoint : null
        {custom_endpoints}
    }}
}}

provider "datadog" {{
    api_key = var.datadog_api_key
    app_key = var.datadog_app_key
}}
"""
    with open(f'{args.directory}/spw/provider.tf', 'w') as f:
        f.write(provider_tf_content)
    print_success(f"Finishing to create provider.tf")

def create_aws_backend(args):
    print_message('Creating backend.tf for backend configuration')
    version = "~> 5.0"
    backend_tf_content = f"""terraform {{
    required_providers {{
        aws = {{
            source  = "hashicorp/aws"
            version = "{version}"
        }}
        datadog = {{
            source  = "DataDog/datadog"
            version = "3.36.0"
        }}
        http-full = {{
            source  = "salrashid123/http-full"
            version = "1.2.0"
        }}
    }}

    backend "remote" {{
        hostname     = "{os.getenv('TFE_HOST')}"
        organization = "{os.getenv('TFE_ORG')}"

        workspaces {{
            name = "{os.getenv('TF_WORKSPACE')}"
        }}
    }}
}}
"""
    with open(f'{args.directory}/spw/backend.tf', 'w') as f:
        f.write(backend_tf_content)
    print_success(f"Finishing to create backend.tf")

def create_vault_variables(args):
    print_message("Creating vault_variables.tf for backend configuration")
    vault_variables_content = """variable "vault_role_name" {
    description = "vault role name"
    type        = string
    default     = null
}

variable "vault_address" {
    description = "vault address"
    type        = string
    default     = "https://vault-enterprise-prod.corp.internal.example.com"
}

variable "vault_creds_workspace" {
    description = "Name of the Vault namespace"
    type        = string
    default     = null
}

variable "destination_region" {
    description = "Destination region for the provider"
    type        = string
    default     = "us-east-2"
}
"""
    with open(f'{args.directory}/spw/vault_variables.tf', 'w') as f:
        f.write(vault_variables_content)
    print_success(f"Finishing to create vault_variables.tf")

def create_endpoint_variables(args):
    print_message("Creating endpoint_variables.tf for backend configuration")
    endpoint_variables_content = """variable "endpoints" {
    description = "Custom VPC endpoints"
    type        = map(string)
    default     = null
}

variable "s3_ue1_interface_endpoint"{
  description = "S3 Interface Endpoint in Shared account UE1"
  type        = string
  default     = "https://bucket.vpce-0ca566c45efe32548-6uiskg1g.s3.us-east-1.vpce.amazonaws.com"
}

variable "s3_ue2_interface_endpoint"{
  description = "S3 Interface Endpoint in Shared account UE2"
  type        = string
  default     = "https://bucket.vpce-041481e5048c80fce-70txxpqr.s3.us-east-2.vpce.amazonaws.com"
}

variable "glue_ue1_interface_endpoint"{
  description = "glue Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-05185314dd2e49510-gyzauip0-us-east-1c.glue.us-east-1.vpce.amazonaws.com"
}

variable "logs_ue1_interface_endpoint"{
  description = "logs ue1 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0f53c2d71e64e6762-l20xqdva.logs.us-east-1.vpce.amazonaws.com"
}

variable "logs_ue2_interface_endpoint"{
  description = "logs ue2 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-06a5c0ecd651d2994-uh7l3ml8.logs.us-east-2.vpce.amazonaws.com"
}

variable "sqs_ue1_interface_endpoint"{
  description = "sqs Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0fc3384b1060eb49e-iq7bkfpl.sqs.us-east-1.vpce.amazonaws.com"
}

variable "events_ue1_interface_endpoint"{
  description = "events Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-06adbdfa7e9a89e0f-0ktjwm42.events.us-east-1.vpce.amazonaws.com"
}

variable "step_function_ue1_interface_endpoint"{
  description = "Step Function ue1 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-05229c3c3a69d0318-8efyhkd3.states.us-east-1.vpce.amazonaws.com"
}

variable "step_function_ue2_interface_endpoint"{
  description = "Step Function ue2Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-064be1b5e10763b76-umi0ytan.states.us-east-2.vpce.amazonaws.com"
}

variable "kinesis_ue1_interface_endpoint"{
  description = "kinesis ue1 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0721f1bf88e127857-ir18s80p.kinesis.us-east-1.vpce.amazonaws.com"
}

variable "kinesis_ue2_interface_endpoint"{
  description = "kinesis ue2 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0c2b28fbe04dd5e98-hv6yohs7.kinesis.us-east-2.vpce.amazonaws.com"
}
variable "athena_ue1_interface_endpoint"{
  description = "athena ue1 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0e50235af9d008e68-vscfja4s.athena.us-east-1.vpce.amazonaws.com"
}

variable "athena_ue2_interface_endpoint"{
  description = "athena ue2 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-05a769409248e8780-7cyym7h8.athena.us-east-2.vpce.amazonaws.com"
}

variable "s3_uw2_interface_endpoint"{
  description = "S3 Interface Endpoint in Shared account UW2"
  type        = string
  default     = "https://bucket.vpce-0162ca0300e1c2631-4ziubx48.s3.us-west-2.vpce.amazonaws.com"
}

variable "athena_uw2_interface_endpoint"{
  description = "athena uw2 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0bb1622edfe5dad82-j8nmpdjp.athena.us-west-2.vpce.amazonaws.com"
}

variable "logs_uw2_interface_endpoint"{
  description = "logs uw2 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0212b347353bed8fa-wlimlqjo.logs.us-west-2.vpce.amazonaws.com"
}

variable "kinesis_uw2_interface_endpoint"{
  description = "kinesis uw2 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0882a0ef53f9536e3-p22lh3xa.kinesis.us-west-2.vpce.amazonaws.com"
}

variable "step_function_uw2_interface_endpoint"{
  description = "Step Function uw2 Interface Endpoint in Shared account"
  type        = string
  default     = "https://vpce-0a422d4c5aac3ec66-9hpdx2vr.states.us-west-2.vpce.amazonaws.com"
}
"""
    with open(f'{args.directory}/spw/endpoint_variables.tf', 'w') as f:
        f.write(endpoint_variables_content)
    print_success(f"Finishing to create endpoint_variables.tf")

def create_datasync_provider(args):
    # Search for the datasync module in .tf files
    cwd = os.getcwd()
    print_info("current location")
    print(cwd) 
    datasync_module = subprocess.run(
        ["grep", "-r", "datasync-module/aws", "--include=*.tf", "--exclude-dir=.terraform", f"{args.directory}/spw"],
        text=True, capture_output=True
    ).stdout
    print_debug(f" datasync is running {datasync_module}")
    if datasync_module:
        print_info("Adding providers for Datasync module")
        with open(f"{args.directory}/spw/provider.tf", "a") as f:
            f.write("""
## Datasync providers
provider "aws" {
  region     = var.region
  access_key = data.vault_aws_access_credentials.creds.access_key
  secret_key = data.vault_aws_access_credentials.creds.secret_key
  token      = data.vault_aws_access_credentials.creds.security_token
  alias      = "source_provider"
}

provider "aws" {
  region     = var.destination_region
  access_key = data.vault_aws_access_credentials.creds.access_key
  secret_key = data.vault_aws_access_credentials.creds.secret_key
  token      = data.vault_aws_access_credentials.creds.security_token
  alias      = "destination_provider"
}
""")
        print_success("Finished creating provider.tf for Datasync providers.")
    else:
        print_info("Datasync module not found")

def create_sql_provider(args):
    # Search for SQL modules in .tf files
    modules = ["postgresql-enterprise-module/aws", "sqlserver-enterprise-module/aws", "mysql-enterprise-module/aws"]
    results = [subprocess.run(
        ["grep", "-r", module, "--include=*.tf", "--exclude-dir=.terraform", "."],
        text=True, capture_output=True
    ).stdout for module in modules]

    if all(results):
        print_info("Adding providers for SQL modules")
        with open(f"{args.directory}/spw/provider.tf", "a") as f:
            f.write("""
## SQL providers
provider "aws" {
  region     = var.region
  access_key = data.vault_aws_access_credentials.creds.access_key
  secret_key = data.vault_aws_access_credentials.creds.secret_key
  token      = data.vault_aws_access_credentials.creds.security_token
  alias      = "source_region"
}

provider "aws" {
  region     = var.destination_region
  access_key = data.vault_aws_access_credentials.creds.access_key
  secret_key = data.vault_aws_access_credentials.creds.secret_key
  token      = data.vault_aws_access_credentials.creds.security_token
  alias      = "destination_region"
}
""")
        print_file_contents("{args.directory}/spw/provider.tf")
        print("Finished creating provider.tf for SQL providers.")


###########################################################################################
###########################################################################################
###########################################################################################
    
###########################################################################################
###########################  TFE FUNCTIONS ################################################
###########################################################################################
def create_datadog_variables(args):
    print_message('Creating datadog_variables.tf for backend configuration')
    
    datadog_variables_content = """
variable "datadog_api_key" {
  description = "datadog api key"
  type        = string
}

variable "datadog_app_key" {
  description = "datadog app key"
  type        = string
}
"""
    with open(f'{args.directory}/spw/datadog_variables.tf', 'w') as f:
        f.write(datadog_variables_content)

def export_datadog_keys(args):
    # Set variables for Vault
    tfvars, path = find_tfvars_file(os.getenv('BRANCH_NAME'), args)
    account_id = extract_account_name_from_tfvars(args, path[0])
    if args.debug: 
        print_debug(f"Account id is : {account_id}")
    fetch_account_config(args, account_id)
    set_vault_environment_variables_from_json(f'{args.build_directory}/input.json')
    set_vault_secret_id(args, os.getenv("BRANCH_NAME"))
    vault_url = os.getenv('VAULT_ADDR')  
    role_id = os.getenv('VAULT_ROLE_ID')
    secret_id = os.getenv('VAULT_SECRET_ID')
    namespace = os.getenv('VAULT_NAMESPACE').upper()
    
    print_message(f"Logging into Vault {vault_url}")
    # Log in to Vault and get the VAULT_TOKEN
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
    
    try:
        # Define the path to the secrets in Vault
        api_key_path = 'secrets/cfg-aws-cldsvcs-devops/datadog/api_key'
        app_key_path = 'secrets/cfg-aws-cldsvcs-devops/datadog/app_key'

        # Use the HVAC client to get the key pair data
        print_info("clinet token : {}".format(client.token))
        os.environ['VAULT_TOKEN'] = client.token

        if args.debug:
            os.environ['VAULT_SKIP_VERIFY'] = "true" 

        # Fetch the private key data

        vault_get_cmd = ['vault', 'kv', 'get', '-format=json', f"{api_key_path}"]
        key_data_json = subprocess.check_output(vault_get_cmd, text=True)
        key_data = json.loads(key_data_json)
        api_key_data = key_data['data']['data']  # This line might need adjustment based on actual JSON structure
        api_key = api_key_data['ddapikey']

        vault_get_cmd = ['vault', 'kv', 'get', '-format=json', f"{app_key_path}"]
        key_data_json = subprocess.check_output(vault_get_cmd, text=True)
        key_data = json.loads(key_data_json)
        app_key_data = key_data['data']['data'] # This line might need adjustment based on actual JSON structure
        app_key = app_key_data['ddappkey']

        if args.debug:
            print_debug(f"api key : {api_key}")
            print_debug(f"app key : {app_key}")

        print_success("Got the DATADOG keys!!!")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    
    # Append the keys to the .tfvars file in the specified target directory
    tf_vars = os.getenv('TF_VARS')
    tfvars_path = os.path.join(f'{args.directory}', f"tfvars/{tf_vars}.tfvars")

    print_info(f"opening file at : {tfvars_path} to add keys")
    
    with open(tfvars_path, 'a') as f:
        f.write(f"\ndatadog_api_key = \"{api_key}\"\n")
        f.write(f"datadog_app_key = \"{app_key}\"\n")
        f.write("\n")

    # Optionally print the contents of the tfvars file (similar to 'less' command)
    with open(tfvars_path, 'r') as f:
        print(f.read())

def set_azure_provider(args):
    try:
        print_message("Creating Provider.")
        create_azure_provider(args)

        print_info("Getting workspace ID and URL")
        id, url = get_workspace_id(args, os.getenv('TFE_HOST'), os.getenv('TFE_ORG'), os.getenv('TF_WORKSPACE'), os.getenv('TFE_TOKEN') )

        print_message("Validate Backend /  Workspace exists.")
        validate_backend(args, url, os.getenv('TFE_TOKEN'))

        print_message("Creating Backend.")
        create_azure_backend(args)

        print_message("Create tf provider block.")
        create_azure_provider_variables(args)
    except LookupError as error:
        print_error(error)
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"General Error:  {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def set_aws_provider(args):
    try:
        print_message("Creating Provider.")
        create_aws_provider(args)

        print_info("Getting workspace ID and URL")
        id, url = get_workspace_id(args, os.getenv('TFE_HOST'), os.getenv('TFE_ORG'), os.getenv('TF_WORKSPACE'), os.getenv('TFE_TOKEN'))

        print_message("Validate Backend /  Workspace exists.")
        validate_backend(args, url, os.getenv('TFE_TOKEN'))

        print_message("Creating Backend.")
        create_aws_backend(args)

        print_message("Create tf provider block.")
        create_endpoint_variables(args)

        print_message("Create vault variables file")
        create_vault_variables(args)

        print_message("Create data sync provider block")
        create_datasync_provider(args)

        print_message("Create sql provider block")
        create_sql_provider(args)
    except LookupError as error:
        print_error(error)
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"General Error: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def copy_auto_tfvars(args):
    # Get environment variables
    tf_vars = os.getenv('TF_VARS')  
    branch_name = os.getenv('BRANCH_NAME')  

    # Define the source and destination paths
    source_path = os.path.join(args.directory, 'tfvars', f"{tf_vars}.tfvars")
    destination_path = os.path.join(args.directory, 'spw', f"{branch_name}.auto.tfvars")

    # Copy and rename the file
    try:
        # Copy the file from source to destination with new name
        shutil.copy(source_path, destination_path)
        print_info(f"File copied from {source_path} to {destination_path}")
        print_success(f"Completed coping {tf_vars}.auto.tfvars")
    except FileNotFoundError:
        print_error(f"Error: The source file {source_path} does not exist.")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def process_tfvars(args):
    vault_workspace = ""
    try:
        tfvars_file = (f"{args.directory}/spw/{os.environ['BRANCH_NAME']}.auto.tfvars")
        with open(tfvars_file, 'r') as file:
            for line in file:
                if 'vault_creds_workspace' in line and not line.strip().startswith('#'):
                    # Extracting the value after the equals sign and stripping potential quotes and extra spaces
                    match = re.search(r'=\s*"?(.*?)"?\s*$', line)
                    if match:
                        vault_workspace =  match.group(1)
                    else: 
                        print_message("No Vault workspace found in tfvar file.")
    except FileNotFoundError:
        print(f"Error: The file {tfvars_file} does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    cloud = os.getenv('CLOUD')

    if not vault_workspace and 'aws' in cloud:
        tfvars_path = f"{args.directory}/spw/{os.getenv('BRANCH_NAME')}.auto.tfvars"
        sysid = '"'
        app_env = f"{os.getenv('BRANCH_NAME')}"

        try:
            with open(tfvars_path, 'r') as file:
                content = file.readlines()
            
            for line in content:
                if 'ApplicationID' in line and not line.strip().startswith('#'):
                    sysid = re.findall(r'=\s*"?([^",\s]+)"?', line.lower())[0]

            if 'sysid' in sysid:
                sysid = f"vault-{sysid}"
            else:
                sysid = f"vault-sysid-{sysid}"

            if 'dev' in app_env:
                sysid += "-p2-uat"
            elif 'prod' in app_env:
                sysid += "-p"
            else:
                sysid += "-p1-uat"

            print_message(f"Adding default vault workspace {sysid}...")
            
            # Append to the .tfvars file
            with open(tfvars_path, 'a') as file:
                file.write(f'\nvault_creds_workspace = "{sysid}"\n')

            print_success(f"Exporting vault_creds_workspace var successfully.")

        except FileNotFoundError:
            print(f"Error: The file {tfvars_path} does not exist.")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards
    else: 
        os.environ['VAULT_CREDS_WORKSPACE']=vault_workspace
        print_message("Skipping vault namespace as it was provided")

##############################################################################
##############################################################################
#TODO : NEED TO UPDATE TO MAP VAULT AUTOMATICALLY.  THIS IS LEGACY LOGIC FOR NOW
##############################################################################
##############################################################################
        
def unset_tf_env_vars():
    # TODO : this needs to be reviewed to understand what is being set 
    # that prevent a terraform run and gets error around workpsace.
    # Create a list of keys to remove to avoid modifying the dictionary while iterating
    keys_to_remove = [key for key in os.environ if key.startswith('TF')]
    print_info("Removing some keys!!!")
    for key in keys_to_remove:
        if key != 'TFE_LATEST_VERSION' and key != 'TFE_TOKEN' and key != 'TFE_HOST':
            print_message(f"Removing environment variable: {key}")
            del os.environ[key]
        else: 
            print_info(f"keeping key : {key}")

def validate_backend(args, url, token):
    try:
        print_info(f"Validating url : {url}")
        headers = {
            'Authorization': f'Bearer {token}',  # Replace with the actual token if needed
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()  # This will raise an HTTPError for bad responses (4xx and 5xx)
        print_success("Validation successful.")
        return response.json()  # or other relevant processing
    except requests.exceptions.HTTPError as http_err:
        print_error(f"HTTP error occurred: {http_err}")  # Handle HTTP errors
        print_error(f"Response status code: {response.status_code}")
        print_error(f"Response content: {response.content}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Raising the exception to exit the function
    except Exception as err:
        print_error(f"An error occurred: {err}")  # Handle non-HTTP errors
        traceback.print_exc()  # This prints the full stack trace
        raise  # Raising the exception to exit the function

        
def get_workspace_id(args, host, org, workspace_name, token):

    """Retrieve the workspace ID using the Terraform Cloud API."""
    if args.debug: 
        print_debug("Lets look at the token we are using")
        run_shell_command(f"echo $TFE_TOKEN >> {args.directory}/tfe.txt")
        print_debug("print file to check token")
        print_debug("Lets check to make sure the file is avaialble")
        print_debug(f"Looking for workspace {workspace_name}")
        run_shell_command(f"ls -la {args.directory}")
        run_shell_command(f"cat {args.directory}/tfe.txt")
    url = f"https://{host}/api/v2/organizations/{org}/workspaces/{workspace_name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/vnd.api+json"
    }
    print_info(f"Trying get id for : {url}")
    response = requests.get(url, headers=headers, verify=False)  # insecure flag
    if response.status_code == 200:
        return response.json()['data']['id'] , url 
    else:
        print_error(f"Error retrieving workspace ID for {workspace_name}: {response.text}")
        traceback.print_exc()  # This prints the full stack trace
        raise ValueError(f"Error retrieving workspace ID for {workspace_name}: {response.text}")
    
def tf_run(args):
    try : 
        print_info(f"Current directory and content: ")
        run_shell_command("ls -la")
        run_shell_command("pwd")
        print_info(f"Changing to deploy directory {args.build_directory}")
        os.chdir(f"{args.build_directory}")
        print_info(f"Current directory and content: ")
        run_shell_command("ls -la")
        run_shell_command("pwd")
        run_shell_command(f"terraform fmt")
        skip_tf_validate = os.getenv('SKIP_TF_VALIDATE', 'False')
        tf_target = os.getenv('TF_TARGET', 'FALSE')

        # Terraform Init
        if args.debug: 
            os.environ['TF_LOG'] = 'DEBUG'
            print_debug("Unset for testing")
            unset_tf_env_vars()
            print_debug(f"Environment: {os.environ}")
            run_shell_command("env")  # This will print all environment variables available to the subprocess

        create_tf_rc(args, host=os.getenv('TFE_HOST'), token=os.getenv('TFE_TOKEN'))
        print_message("Setting TF Version")


        if args.stage == "plan": 
            print_info(f"Checking current terraform version")
            run_shell_command("terraform --version")
            print_command(f"terraform init")
            run_shell_command(f"terraform init -input=false")
            if args.debug: 
                print_debug("terraform providers lock -platform=linux_amd64")
                run_shell_command("terraform providers lock -platform=linux_amd64")

            # Code Validation
            if skip_tf_validate == "False":
                print_command(f"terraform validate")
                run_shell_command(f"terraform validate")
            else:
                print(f"Skipping terraform validate as SKIP_TF_VALIDATE is {skip_tf_validate}")
            print_command(f"terraform plan")
            if os.getenv("TERRAFORM_DESTROY") == "TRUE":
                print_command(f"terraform destroy plan")
                run_shell_command("terraform plan --destroy")
            else:
               print_command(f"terraform plan")
               run_shell_command("terraform plan")
            print_success(f"Terraform plan completed!!!!")
        elif args.stage == "destroy" or os.getenv("TERRAFORM_DESTROY") == "TRUE":
            print_command("terraform destroy")
            print_info(f"Checking current terraform version")
            run_shell_command("terraform --version")
            try: 
                run_shell_command("terraform destroy --auto-approve")
                print_success(f"Terraform destroy completed!!!!")
            except Exception as e:
                print_error(f"Terraform destroy failed: {e}")
                traceback.print_exc()  # This prints the full stack trace
                raise  # Re-raise the exception to propagate it upwards
        elif args.stage == "apply":
            print_command("terraform apply")
            print_info(f"Checking current terraform version")
            run_shell_command("terraform --version")
            try: 
                run_shell_command("terraform apply --auto-approve")
                print_success(f"Terraform apply completed!!!!")
            except Exception as e:
                print_error(f"Terraform apply failed: {e}")
                traceback.print_exc()  # This prints the full stack trace
                raise  # Re-raise the exception to propagate it upwards
    except Exception as e:
        print_error(f"Terraform run failed: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

###########################################################################################
###########################################################################################
###########################################################################################

def tf_plan_apply(args):
    try: 
        if args.stage == "plan":
            print_info("Export datadog keys from vault .......")
            export_datadog_keys(args)
            print_success("Proccessed datadog keys")
            print_info("Create data dog variables for terraform ......")
            create_datadog_variables(args)
            print_success("created datadog variables")
            print_info(f"moving tf var file {os.environ['TF_VARS']} to be *.auto.tfvars .....")
            copy_auto_tfvars(args)
            print_success("copied auto tfvars")
            print_info(f"processing tfvars ......")
            process_tfvars(args)
            print_success("Finished processing tfvars")
        if args.stage == "destroy" or os.getenv("TERRAFORM_DESTROY") == "TRUE":
            print_debug("Running destroy now...")
            copy_auto_tfvars(args)
            print_success("Copied auto tfvars for destroy")
            print_info(f"Processing TF vars for destroy ......")
            process_tfvars(args)
            print_success("Finished processing TF vars for destroy")

        tf_run(args)
        print_success("Finished TF run")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def extract_account_name_from_tfvars(args, tfvars_path):
    """
    Extracts the account_name from the given tfvars file content.
    
    Parameters:
    args (Namespace): Arguments passed to the script.
    tfvars_path (str): Path to the tfvars file.
    
    Returns:
    str: The value of account_name if found, else None.
    """
    # Define the regex pattern to match the account_name
    pattern = r'^\s*account_name\s*=\s*"([^"]+)"\s*$'
    
    if args.debug: 
        print_debug(f"Path for tfvars is : {tfvars_path}")
    
    # Read the content of the tfvars file
    try:
        with open(tfvars_path, 'r') as file:
            tfvars_content = file.read()
    except FileNotFoundError:
        if args.debug:
            print_debug(f"File not found: {tfvars_path}")
        return None

    # Search for the pattern in the content
    match = re.search(pattern, tfvars_content, re.MULTILINE)
    if args.debug: 
        print_debug(f"Match for account name is : {match}")
    
    if match:
        # Return the captured group which is the value of account_name
        return match.group(1)
    return None
     
    
