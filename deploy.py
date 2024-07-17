from .config import set_tfe_configs, set_terraform_version, fetch_config
from .utils import print_message, print_command, print_error, print_success, print_debug, print_info,find_tfvars_file
from .utils import load_config_file, copy_files, checkout_repo, check_required_env_vars, run_shell_command
from .terraform import set_azure_provider, set_aws_provider, tf_plan_apply
import sys
import traceback
import os
import re
import glob

def get_repo_prefix(repo_name):
    """
    Extract the repository name from a Bitbucket URL or return the original name if it's not a URL.
    Remove the '-aws' segment and anything following it.
    """
    # Check if the repo_name is a URL
    if re.match(r'^https?://', repo_name):
        # Extract the repository name from the URL
        repo_name = repo_name.rstrip('/').split('/')[-1]
    
    # Remove the '-aws' segment and anything following it
    return re.sub(r'-aws.*$', '', repo_name)

def construct_tfe_workspace(args):
    """Construct the TF_WORKSPACE name using REPO_URL and BRANCH_NAME environment variables."""
    repo_url = os.getenv('REPO_URL')
    branch_name = os.getenv('BRANCH_NAME')

    if args.debug: 
        print_debug(f"Repo url is {repo_url}")
        print_debug(f"Branch name is {branch_name}")
    
    if not repo_url or not branch_name:
        raise ValueError("REPO_URL and BRANCH_NAME environment variables must be set.")

    repo_prefix = get_repo_prefix(repo_url)
    if args.debug: 
        print_debug(f"Repo prefix is {repo_prefix}")
    tfvars_name, file_location = find_tfvars_file(branch_name, args)
    tf_workspace = f"{repo_prefix}-{tfvars_name}"
    print_message("Set ENV for TF_WORKSPACE")
    os.environ['TF_WORKSPACE'] = tf_workspace
    return tf_workspace

def get_spw(args): 

    print_info("Cleaning up spw/ for new deploy")
    run_shell_command(f"rm -rf {args.directory}/spw")
    print_message("Check ENV variables needed for SPW")
    check_required_env_vars(['CLOUD','REPO_ORGANIZATION','SUPPORTED_PRODUCT_WORKLOAD','SUPPORTED_PRODUCT_WORKLOAD_VERSION', 'TERRAFORM_DESTROY'])

    repo_organization = os.getenv('REPO_ORGANIZATION')
    cloud = os.getenv('CLOUD')
    supported_product_workload = os.getenv('SUPPORTED_PRODUCT_WORKLOAD')
    waas_branch = os.getenv('SUPPORTED_PRODUCT_WORKLOAD_VERSION')

    
    if not all([repo_organization, cloud, supported_product_workload, waas_branch]):
        raise ValueError("One or more required environment variables are not set.")

    # Checkout repos
    spw_repo_url = f"https://bitbucket.corp.internal.citizensbank.com/scm//{repo_organization}/tfe-{cloud}-{supported_product_workload}.git"
    checkout_repo(args, spw_repo_url, waas_branch, f'{args.directory}/spw')

    shared_scripts_repo_url = f"{os.environ['TFE_CLOUD_SCRIPTS_URL']}"
    checkout_repo(args, shared_scripts_repo_url, 'master', f'{args.directory}/cloud-shared-scripts')

    #Check with DUSTIN why this is needed? 
    # Check if SUPPORTED_PRODUCT_WORKLOAD contains 'rds' or 'lambda'
    #is_rds_or_lambda = 'rds' in supported_product_workload.lower() or 'lambda' in supported_product_workload.lower()

    # Copy .tpl files if SUPPORTED_PRODUCT_WORKLOAD does not contain 'rds' or 'lambda'
    # if not is_rds_or_lambda:
    #     tpl_files_exist = subprocess.run(['find', '.', '-name', '*.tpl'], capture_output=True, text=True).returncode == 0

    #     if tpl_files_exist:
    #         print_message("Copying .tpl files...") 
    #         copy_files('*.tpl', 'spw')
    #     else:
    #         print("No .tpl files found. Skipping copying.")
    # else:
    #     print_info("Pattern contains 'rds' or 'lambda'. Skipping copying of .tpl files.")


    # Copy other folders based on conditions
    print_message("Copy *.tpl files...")
    environment_name = os.getenv('BRANCH_NAME')

    # Copy tpl file only for dev environment
    if environment_name == "dev":
        copy_files(f'{args.directory}/*.tpl', f'{args.directory}/spw')
    else :
    # Create empty userdata.tpl for all non-dev environments    
        file_path = os.path.join(f'{args.directory}/spw', 'userdata.tpl')
        with open(file_path, 'w') as file:
            pass

    print_message("Copy lambda folder...")
    copy_files(f'{args.directory}/lambda/*', f'{args.directory}/spw')

    print_message("Copy S3 policy arns folder...")
    copy_files(f'{args.directory}/s3-policy-arns/*', f'{args.directory}/spw')

    print_message("Copy config folder...")
    copy_files(f'{args.directory}/config/*', f'{args.directory}/spw')

    print_message("Deleting duplicate provider for testing if it exists")
    duplicate_provider_path = f'{args.directory}/spw/provider_integration_test.tf'
    if os.path.exists(duplicate_provider_path):
        os.remove(duplicate_provider_path)
    else:
        print("No duplicate provider for testing found. Skipping...")

    print("Copy Cloud Shared Scripts folder...")
    copy_files(f'{args.directory}/cloud-shared-scripts/cloud-scripts/*', f'{args.directory}/spw/cloud-scripts/')


def deploy_command(args):
    try:
        fetch_config(args)
        print_info("Configuration fetched successfully:")
        print_message("Load workload.config")
        load_config_file(f"{args.directory}/workload.config")

        
        if args.stage == "plan":
            print("Terraform apply")

            print_message("Setting TF Version")
            set_terraform_version(args)
            print_info("set_terraform_version was called")

            print_info("Starting Deploy !!!")
            deploy_type = args.type.lower()

            # Need to set the workspace first 
            print_message("Setting TFE Workspace")
            tf_workspace = construct_tfe_workspace(args)
            print_info(f"TF_WORKSPACE is : {tf_workspace}")

            print_message("Now set TFE configs")
            set_tfe_configs(args)

            print_message("Get SPW for Workload Deploy")
            get_spw(args)

            print_message("Setting Provider and Backend files")
            if args.debug:
                print_info(f"setting for cloud : {os.environ['CLOUD']}")
            if os.environ['CLOUD'] == "azure": 
                set_azure_provider(args)
            elif os.environ['CLOUD'] == "aws": 
                set_aws_provider(args)
            else: 
                print_info("NO landing zone found? ")
        else: 
            print("Terraform apply")
            print_debug(f"Current stage:{args.stage}")

        print_message("Terraform plan/apply")
        tf_plan_apply(args)

    except ValueError as e:
        print_error(f"Configuration error: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

