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

