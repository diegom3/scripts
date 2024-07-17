import argparse
import os
import sys
import traceback
import shutil
from .build import build_command
from .deploy import deploy_command
from .config import fetch_config
from .utils import print_message, print_command, print_error, print_success, print_debug, print_info
from .copy import copy_command

def main():
    parser = argparse.ArgumentParser(description="Fetch configuration for bifrost-bridge.")
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    subparsers = parser.add_subparsers(help='sub-command help', dest='command')
    subparsers.required = True

    # Create a subparser for the 'config' command
    parser_config = subparsers.add_parser('config', help='Fetch configuration from URL or file')
    parser_config.add_argument('--url', help='URL to fetch the configuration from', default=None)
    parser_config.add_argument('--file', help='File path to load the configuration from', type=str, default=None)
    parser_config.set_defaults(func=config_command)

    # 'build' command parser setup
    parser_build = subparsers.add_parser('build', help='Build the project with the provided configuration')
    parser_build.add_argument('--url', help='URL to fetch the configuration from', default=None)
    parser_build.add_argument('--file', help='File path to load the configuration from', type=str, default=None)
    parser_build.add_argument('--directory', help='Working directory for the build process', default='.')
    parser_build.add_argument('--type', type=str, help='Type of the build (e.g., ami, docker)', required=True, default=os.getenv('BUILD_TYPE', 'default'))
    parser_build.add_argument('--stage', type=str, choices=['pr', 'merge'], help='Stage of the build process', required=True)
    parser_build.set_defaults(func=build_command)

    # 'deploy' command parser setup
    parser_deploy = subparsers.add_parser('deploy', help='Deploy the project with the provided configuration')
    parser_deploy.add_argument('--url', help='URL to fetch the configuration from', default=None)
    parser_deploy.add_argument('--file', help='File path to load the configuration from', type=str, default=None)
    parser_deploy.add_argument('--type', type=str, help='Type of the deployment', required=True)
    parser_deploy.add_argument('--directory', help='Working directory for the deployment process', required=True)
    parser_deploy.add_argument('--stage', help='Stage of the deployment', required=True)
    parser_deploy.set_defaults(func=deploy_command)

    # Add 'copy' command parser setup
    parser_copy = subparsers.add_parser('copy', help='Copy AMI between environments using specified configurations')
    parser_copy.add_argument('--type', type=str, help='Type of copy operation (e.g., ami)', required=True)
    parser_copy.add_argument('--config', help='Directory containing copy configs', required=True)
    parser_copy.add_argument('--directory', help='Directory containing .tfvars files', required=True)
    parser_copy.add_argument('--from-env', type=str, required=True, help='Source environment (e.g., dev)')
    parser_copy.add_argument('--to-env', type=str, required=True, help='Destination environment (e.g., qa)')
    parser_copy.set_defaults(func=copy_command)


    args = parser.parse_args()

    # Modify args for build command to include build_directory and force deletion/recreation
    if args.command == 'build':
        args.build_directory = os.path.join(args.directory, "build_artifact")
        if os.path.exists(args.build_directory):
            print_info("Removing existing build directory")
            shutil.rmtree(args.build_directory)
        print_info("Creating new build directory")
        os.makedirs(args.build_directory)
    
    # Modify args for deploy command to include build_directory and force deletion/recreation
    if args.command == 'deploy':
        args.build_directory = os.path.join(args.directory, "spw")
        if os.path.exists(args.build_directory) and args.stage == "plan":
            print_info("Removing existing build directory")
            shutil.rmtree(args.build_directory)

    # Modify args for copy command to include build_directory and force deletion/recreation
    if args.command == 'copy':
        args.build_directory = os.path.join(args.config, "build_artifact")
    

    # Execute the function associated with the selected subcommand
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(2)

def config_command(args):
        # Ensure at least one source of configuration is provided for config and build commands
    print_info(f"BIFROS CONFIG : {os.getenv('BIFROST_BRIDGE_CONFIG_URL')}")
    if not args.url and args.file and os.getenv('BIFROST_BRIDGE_CONFIG_URL'):
        print_error("No configuration source provided. Please use --url or --file or set BIFROST_BRIDGE_CONFIG_URL.")
        print("Exiting with code 2")  # Debug print
        sys.exit(2)
    try:
        config = fetch_config(args)
        print_info("Configuration fetched successfully")
    except Exception as e:
        print_error(f"Error fetching configuration: {e}")
        traceback.print_exc()  # This prints the full stack trace
        sys.exit(1)  # Exit with status code 1 to indicate error
if __name__ == "__main__":
    main()
