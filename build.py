import sys
import os
import shutil
from .config import fetch_config, fetch_packer_config, run_shell_command,set_ami_users
from .config import set_ami_config, set_aws_creds, fetch_account_config
from .utils import generate_code_hash, ami_exists_with_tag, fetch_vault_secrets, check_snow
from .utils import print_file_contents, check_snow, print_file_contents, set_os_environment_variables_from_json
from .utils import get_latest_golden_ami, compare_latest_golden_ami, set_os_environment_variables_from_json
from .utils import generate_code_hash, ami_exists_with_tag, fetch_vault_secrets, checkout_repo
import json
import subprocess
import traceback
import threading
from queue import Queue, Empty
from threading import Thread
from .ansible import parse_ansible_requirements
from .utils import print_message, print_command, print_error, print_success, print_debug, print_info


# def enqueue_output(pipe, queue):
#     for line in iter(pipe.readline, ''):
#         queue.put(line)
#     pipe.close()


def run_packer_command(args, command):
    print_info(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_queue = Queue()
    stderr_queue = Queue()

    def enqueue_output(pipe, queue):
        for line in iter(pipe.readline, b''):
            queue.put(line.decode())
        pipe.close()

    stdout_thread = Thread(target=enqueue_output, args=(process.stdout, stdout_queue))
    stderr_thread = Thread(target=enqueue_output, args=(process.stderr, stderr_queue))

    stdout_thread.start()
    stderr_thread.start()

    ami_id = None

    while stdout_thread.is_alive() or stderr_thread.is_alive() or not stdout_queue.empty() or not stderr_queue.empty():
        try:
            stdout_line = stdout_queue.get_nowait().strip()
            if stdout_line:
                print_info(stdout_line)
        except Empty:
            pass

        try:
            stderr_line = stderr_queue.get_nowait().strip()
            if stderr_line:
                if "ERROR" in stderr_line:
                    print_error(stderr_line)
                elif "WARN" in stderr_line:
                    print_message(stderr_line)
                else:
                    print_info(stderr_line)
        except Empty:
            pass

    stdout_thread.join()
    stderr_thread.join()

    process.wait()

    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command)

    return True

def packer_build(args, build_directory, ami_os_type): 

    try:
        print_info("Setting configs from OS_Env.json")

        try:
            set_os_environment_variables_from_json(f"{args.build_directory}/OS_Env.json", ami_os_type)
        except TypeError as e:
            print_error(f"Type error : {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards
        except Exception as e:
            print_error(f"General Error: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards



        try:
            print_info("Fetching KeyPair from Vault")
            fetch_vault_secrets(args,os.environ.get('AMI_ACCOUNT'))
        except Exception as e:
            print_error(f"Error getting vault creds: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards

        try: 
            print_info("Check SYSID in SNOW")
            business_mapping = check_snow(args, os.environ.get('SYSID_APP', ''))
            print_info("Business mapping {m}".format(m=business_mapping))
        except Exception as e:
            print_error(f"Error getting SNOW confirmation.: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards
            
        os_type = ami_os_type.split('-')[0]

        print_info("Running packer build for os : {}".format(os_type))
        try:
            print_info("Get packer configs for my OS {o} first and write to {d}".format(o=os_type, d=build_directory))
            fetch_packer_config(args, os_type)
        except Exception as e:
            print_error(f"Error getting packer configs.: {e}")
            traceback.print_exc()  # This prints the full stack trace
            raise  # Re-raise the exception to propagate it upwards

        if os_type == "mac":
            print_info("For mac builds we need a dedicated host")
            print_info("Checking for dedicated host")
            return True

            # # Define AWS Region and Instance Type
            # # Check for available dedicated hosts
            # cmd_describe_hosts = [
            #     'aws', 'ec2', 'describe-hosts',
            #     '--region', aws_region,
            #     '--filters', 'Name=auto-placement,Values=on',
            #     f'Name=instance-type,Values={instance_type}'
            # ]
            # result = subprocess.run(cmd_describe_hosts, capture_output=True, text=True)
            # host_details = result.stdout
            # print_info("Check if capacity is available")
            # print(host_details)

            # # Save to a JSON file
            # with open('capacity.json', 'w') as file:
            #     file.write(host_details)

            # # Check capacity using jq-style filtering in Python
            # with open('capacity.json', 'r') as file:
            #     data = json.load(file)
            #     capacity = any(
            #         host for host in data.get('Hosts', [])
            #         if any(cap for cap in host.get('AvailableCapacity', {}).get('AvailableInstanceCapacity', [])
            #             if cap['InstanceType'] == 'mac1.metal' and cap['AvailableCapacity'] > 0)
            #     )

            # if not capacity:
            #     print_info("No existing capacity host found. Creating a new one...")
            #     sysid = os.getenv('SYSID')
            #     print(sysid)
            #     two_days_ahead = (datetime.datetime.now() + datetime.timedelta(days=2)).strftime('%Y-%m-%d')
            #     print_info("Terminate day will be", two_days_ahead)

            #     # Allocate the host with additional TerminateOn tag
            #     cmd_allocate_hosts = [
            #         'aws', 'ec2', 'allocate-hosts',
            #         '--region', aws_region,
            #         '--instance-type', instance_type,
            #         '--auto-placement', 'on',
            #         '--availability-zone', f"{aws_region}b",
            #         '--quantity', '1',
            #         '--query', 'HostIds[0]',
            #         '--output', 'text',
            #         '--tag-specifications', f'ResourceType=dedicated-host,Tags=[{{Key=ApplicationID,Value={sysid}}},{{Key=TerminateOn,Value={two_days_ahead}}}]'
            #     ]
            #     result = subprocess.run(cmd_allocate_hosts, capture_output=True, text=True)
            #     new_host_id = result.stdout.strip()
            #     print_info("Created new dedicated host:", new_host_id)
            # else:
            #     print_info("Using existing dedicated host found in:", host_details)

        elif os_type == "amazon" or ami_os_type == "redhat" :
            print_info("For amazon/linux builds")
            print_info(f"Not alteration to {args.build_directory}/packer_config.json!!!!!!")
            print_file_contents(f"{args.build_directory}/packer_config.json")
        elif os_type == "windows":
            print_info("For window builds")
            return True
            # ansible_run_tags = os.getenv("ANSIBLE_RUN_TAGS")
            # if ansible_run_tags:
            #     # Using a temporary file
            #     with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            #         tmpfile_name = tmpfile.name
                
            #     # Copy the JSON configuration to a temporary file
            #     shutil.copy('cfg_windows.json', tmpfile_name)
                
            #     # Read the existing JSON data
            #     with open(tmpfile_name, 'r') as file:
            #         data = json.load(file)
                
            #     # Modify JSON data
            #     for provisioner in data.get('provisioners', []):
            #         if provisioner.get('type') == "ansible":
            #             # Updating or setting extra_arguments with new values
            #             extra_args = provisioner.get('extra_arguments', [])
            #             extra_args.extend([
            #                 "--extra-vars", "ansible_host={{ build `Host` }}",
            #                 "--extra-vars", "ansible_user=Administrator",
            #                 "--extra-vars", "ansible_password={{ .WinRMPassword }}",
            #                 "--extra-vars", "ansible_connection=winrm",
            #                 "--extra-vars", "ansible_port=5986",
            #                 "--extra-vars", "ansible_winrm_transport=ntlm ansible_winrm_server_cert_validation=ignore",
            #                 "--tags", "{{user `ansible_run_tags`}}",
            #                 "--skip-tags", "{{user `ansible_skip_tags`}}"
            #             ])
            #             provisioner['extra_arguments'] = extra_args
                
            #     # Write the modified data back to the original JSON file
            #     with open('cfg_windows.json', 'w') as file:
            #         json.dump(data, file)
                
            #     # Clean up temporary files
            #     os.remove(tmpfile_name)

        print_info("Running packer build now.")
        print_info(f"Need to get into working directory : {args.build_directory}")
        os.chdir(args.build_directory)
        if args.debug: 
            print_debug("Where are we?")
            run_packer_command(args, "ls -la")
            os.environ['PACKER_LOG'] = "1" 
            for name, value in os.environ.items():
                print_debug(f"{name}={value}")
        
        var_file_1 = f"input.json"
        var_file_2 = "tags.auto.pkrvars.json"
        config_file = "packer_config.json"

        if args.debug:
            print_debug(f"Checking {var_file_1} content: ")
            run_shell_command(f"cat {var_file_1}")
            print_debug(f"Checking {var_file_2} content: ")
            run_shell_command(f"cat {var_file_2}")
            print_debug(f"Checking {config_file} content: ")
            run_shell_command(f"cat {config_file}")
        

        print_info("packer init for plugins")
        run_shell_command(f"packer init template.pkr.hcl")
        print_info("Run ansible-galaxy install of requiements before packer run")
        run_shell_command('ansible-galaxy install -r ansible/requirements.yml -p ansible/playbooks/roles/')

        if args.stage == 'pr':
            if args.debug: 
                print_debug("Let's see where we are and what is in the directory")
                run_shell_command('ls -la')
                run_shell_command('pwd')

                print_info(f"Running packer build -on-error=abort -force -var-file {var_file_1} -var-file {var_file_2} {config_file}")
                run_packer_command(args, f"packer build -on-error=abort -force -var-file {var_file_1} -var-file {var_file_2} {config_file}")
            else:
            	print_info(f"Running packer build -force -var-file {var_file_1} -var-file {var_file_2} {config_file}")
            	run_packer_command(args, f"packer build -force -var-file {var_file_1} -var-file {var_file_2} {config_file}")
            
        
        elif args.stage == 'merge':
            print_info("Running Packer build for merge stage and saving the AMI artifact.")
            if args.debug: 
                print_debug("Let's see where we are and what is in the directory")
                run_shell_command('ls -la')
            print_info("This will copy the ami in pipeline unless it doesn't exist")

        return True
    except Exception as e:
        print_error(f"Error building ami with packer: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards

def build_command(args):
    try:
        build_type = args.type.lower()
        fetch_config(args)  # This will now operate relative to the new working directory
        print_info("Configuration fetched successfully:")

        print_info("Set ami config json")
        set_ami_config(args)

        print_info("Fetch packer configs")
        fetch_account_config(args, os.environ.get('AMI_ACCOUNT'))

        # Here we configure to exclude all hidden files and directories
        exclude_dirs = ['.*',"*build_artifact*"]  # Exclude hidden directories
        ignore_files = ['.*', '*.md*']  # Exclude hidden files

        if args.debug: 
            print_debug("Checking content of build directory")
            run_shell_command(f"ls -al {args.build_directory}")

        print_info("Setting AWS creds from vault")
        set_aws_creds(args, "dev")

        # Assuming generate_
        #  uses the current working directory
        code_hash = generate_code_hash(args, exclude_dirs=exclude_dirs,ignore_files=ignore_files)
        print_info(f"Code hash: {code_hash}")
        print_info("Set CODE_HASH environment variable")
        os.environ['CODE_HASH']=code_hash
    except Exception as e:
        print_error(f"Error fetching configuration or generating code hash: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards


    try:
        # Conditional logic based on build type
        if build_type == 'ami':
            print_info("We need to check the ansible/requirments.yml file")
            parse_ansible_requirements(f'{args.directory}/ansible/requirements.yml')
            print_info("Need to initialize os configuration for AMI build")
            try:
                # Load JSON data from a file
                with open(f'{args.directory}/ami_config.json', 'r') as file:
                    ami_config = json.load(file)
            except FileNotFoundError:
                print_error("Error: The file 'ami_config.json' does not exist.")
                traceback.print_exc()  # This prints the full stack trace
                raise  # Re-raise the exception to propagate it upwards
            except json.JSONDecodeError:
                print_error("Error: JSON decode error in 'ami_config.json'.")
                traceback.print_exc()  # This prints the full stack trace
                raise  # Re-raise the exception to propagate it upwards

            # Get the OS type from environment or use default from JSON
            # Inside build_command function, right before the KeyError line
            print_info(f"ami_config content {ami_config}")

            try: 
                print_info("Set variables for buildling AMI")
                ami_os_type = ami_config[0].get('os_type') if 'AMI_OS_TYPE' not in os.environ else os.environ['AMI_OS_TYPE']
                print_info(f"AMI_OS_TYPE = {ami_os_type}")

                landing_zone = os.environ.get('LANDING_ZONE', '').lower()
                if args.debug:
                    print_debug(f"Debug: Landing Zone is '{landing_zone}'")  # Debug output
                
                repo = None
                landing_zone = os.environ.get('LANDING_ZONE', '').lower()
                if args.debug:
                    print_debug(f"Debug: Landing Zone is {landing_zone}")  # Debug output
                if landing_zone == "aws":
                    repo = os.environ.get('PACKER_AWS_CONFIG_REPO', '')
                elif landing_zone == "azure":
                    repo = os.environ.get('PACKER_AZURE_CONFIG_REPO', '')

                if repo:
                    if args.debug:
                        print_debug(f"OS Config Repo: {repo}")
                        print_debug(f"Config Directory:  {args.build_directory}")
                        print_debug("Checking content of build directory")
                        run_shell_command(f"ls -al {args.build_directory}")
                    
                    print_info(f"Setting os configurations from repo {repo}")
                    checkout_repo(args, repo, os.getenv("PACKER_TAG"), f'{args.build_directory}/os_config')
                    print_info(f"copy packer configs in {args.build_directory}/os_config/resources/com/citizensbank/scripts/packer/* to {args.build_directory} for checking on golden ami")
                    run_shell_command(f'cp -R {args.build_directory}/os_config/resources/com/citizensbank/scripts/packer/* {args.build_directory}')

                    if args.debug: 
                        print_debug("Checking content of build directory")
                        run_shell_command(f"ls -al {args.build_directory}")

                    set_os_environment_variables_from_json(f"{args.build_directory}/OS_Env.json", ami_os_type)


                else:
                    print_info("No repository configured for the specified landing zone.")
                    traceback.print_exc()  # This prints the full stack trace
                    raise RuntimeError("No repository configured for the specified landing zone.")
            except Exception as e:
                print_debug(f"Error with packer build: {e}")
                traceback.print_exc()  # This prints the full stack trace
                raise  # Re-raise the exception to propagate it upwards
            
            # Check new golden_ami exists
            # Retrieve the value of the environment variable AMI_AMIOSVERSIONFILTER
            ami_os_version_filter = os.environ.get('AMI_AMIOSVERSIONFILTER')
            if args.debug: 
                print_debug(f"ami os version filter is : {ami_os_version_filter}")
            # if exits you must rebuild ami.
            print_info("Getting current image if exists")
            ami_exists, ami_details = ami_exists_with_tag(args, code_hash)

            print_info("Get lastest golen ami details.") 

            latest_golden_ami_details = get_latest_golden_ami(args, ami_details, ami_os_version_filter)

            if args.debug: 
                print_debug(f"Latest golden ami details {latest_golden_ami_details}")
                print_debug(f"ami details {ami_details}")
            
            
            if not ami_exists or compare_latest_golden_ami(args, ami_details, latest_golden_ami_details):
                print_info("ami does not exist or there is a new golden ami available for this os, will continue with build...")
                try:
                    
                    if args.debug: 
                        print_debug(f"Content of {args.directory}")
                        print_debug(os.listdir(args.directory))
                        print_debug(f"Content of {args.build_directory}")
                        print_debug(os.listdir(args.build_directory))
                    """Copy packer scripts to packer directory"""
                    print_info("copy ami_config.json and ansible/ to build directory")
                    run_shell_command(f'cp -R {args.directory}/ansible/ {args.build_directory}/ansible')
                    print_info("Delete role/ in playbooks/. This will be built with requirements.yml")
                    run_shell_command(f"rm -rf {args.build_directory}ansible/playbooks/roles")
                    print_info("Copy ami_config.json to build directory")
                    run_shell_command(f"cp {args.directory}/ami_config.json {args.build_directory}")
                    if args.debug: 
                        print_debug(f"Content of {args.directory}")
                        print_debug(os.listdir(args.directory))
                        print_debug(f"Content of {args.build_directory}")
                        print_debug(os.listdir(args.build_directory))
                    packer_build(args, args.build_directory, ami_os_type)
                except Exception as e:
                    print_debug(f"Error with packer build: {e}")
                    traceback.print_exc()  # This prints the full stack trace
                    raise  # Re-raise the exception to propagate it upwards
            else:
                print_info("An AMI with hash {} already exists and is on latest Golden build.".format(code_hash))

                if args.debug:
                    print_debug(f"AMI Details: {ami_details}")
                sys.exit(0)

        elif build_type == 'docker': 
            print_info("Comming Soon")

        sys.exit(0)

    except Exception as e:
        print_error(f"Error with build: {e}")
        traceback.print_exc()  # This prints the full stack trace
        raise  # Re-raise the exception to propagate it upwards
