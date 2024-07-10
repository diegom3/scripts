def check_required_env_vars(required_vars):
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            print_debug(f"Environment variable {var} is missing.")
            raise ValueError(f"Missing required environment variable: {var}")
        print_debug(f"Environment variable {var} is set to {value}")


check_required_env_vars(['CLOUD','REPO_ORGANIZATION','SUPPORTED_PRODUCT_WORKLOAD','SUPPORTED_PRODUCT_WORKLOAD_VERSION', 'TERRAFORM_DESTROY'])



import os

def print_debug(message):
    print(message)

def check_required_env_vars(required_vars):
    if 'TERRAFORM_DESTROY' in required_vars:
        value = os.getenv('TERRAFORM_DESTROY')
        if not value:
            os.environ['TERRAFORM_DESTROY'] = 'false'
            print_debug("Environment variable TERRAFORM_DESTROY was not provided, setting to false.")
        else:
            print_debug(f"Environment variable TERRAFORM_DESTROY is set to {value}")
        required_vars.remove('TERRAFORM_DESTROY')
    
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            print_debug(f"Environment variable {var} is missing.")
            raise ValueError(f"Missing required environment variable: {var}")
        print_debug(f"Environment variable {var} is set to {value}")

check_required_env_vars(['CLOUD', 'REPO_ORGANIZATION', 'SUPPORTED_PRODUCT_WORKLOAD', 'SUPPORTED_PRODUCT_WORKLOAD_VERSION', 'TERRAFORM_DESTROY'])



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

        tf_run(args)
        print_success("Finished TF run")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards


def tf_plan_destroy(args):
    try:
        if args.stage == "destroy" or os.getenv("TERRAFORM_DESTROY", "false").lower() == "true":
            print_info("Exporting Datadog keys from vault for destroy .......")
            export_datadog_keys(args)
            print_success("Processed Datadog keys for destroy")
            print_info("Creating Datadog variables for Terraform destroy ......")
            create_datadog_variables(args)
            print_success("Created Datadog variables for destroy")
            print_info(f"Moving TF var file {os.environ['TF_VARS']} to be *.auto.tfvars for destroy .....")
            copy_auto_tfvars(args)
            print_success("Copied auto tfvars for destroy")
            print_info(f"Processing TF vars for destroy ......")
            process_tfvars(args)
            print_success("Finished processing TF vars for destroy")

            tf_run_destroy(args)
            print_success("Finished TF destroy run")
        else:
            print_info("Stage is not 'destroy' and TERRAFORM_DESTROY is not set to true. Skipping destroy steps.")
    except Exception as e:
        print_error(f"An unexpected error occurred during destroy: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards


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


