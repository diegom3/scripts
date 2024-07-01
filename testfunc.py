def check_required_env_vars(required_vars):
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            print_debug(f"Environment variable {var} is missing.")
            raise ValueError(f"Missing required environment variable: {var}")
        print_debug(f"Environment variable {var} is set to {value}")


check_required_env_vars(['CLOUD','REPO_ORGANIZATION','SUPPORTED_PRODUCT_WORKLOAD','SUPPORTED_PRODUCT_WORKLOAD_VERSION', 'TERRAFORM_DESTROY'])
