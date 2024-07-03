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


