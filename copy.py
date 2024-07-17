import boto3
from botocore.exceptions import ClientError
import os
import sys
import json
import traceback
from .utils import print_message, print_command, print_error, print_success, print_debug, print_info
from .utils import find_tfvars_file, run_shell_command
from .config import set_aws_creds, fetch_config, fetch_account_config
from .terraform import extract_account_name_from_tfvars



def read_kms_key_from_tfvars(tfvars_path):
    """
    Reads the KMS key alias from a Terraform variables file.
    
    Args:
    tfvars_path (str): Path to the `.tfvars` file.
    
    Returns:
    str: The value of the KMS key alias.
    """
    kms_key_alias = ""
    print_info(f"Attempting to read file : {tfvars_path[0]}")
    try:
        with open(tfvars_path[0], 'r') as file:
            for line in file:
                if "ebs_kms_key_alias" in line:
                    # Assumes the line format is `key = "value"`
                    kms_key_alias = line.split('=')[1].strip().replace('"', '')
                    print_info(f"Found key : {kms_key_alias} in file {tfvars_path[0]}")
                    break
    except FileNotFoundError:
        print(f"File not found: {tfvars_path}")
    return kms_key_alias

def update_environment_tag(ami_details, new_environment_value):
    """
    Update the 'Environment' tag in ami_details to a new value.

    Args:
    ami_details (dict): A dictionary containing details of the AMI, including its tags.
    new_environment_value (str): The new value for the 'Environment' tag.

    Returns:
    dict: The updated ami_details with the modified 'Environment' tag.
    """
    # Check if 'Tags' exists in ami_details
    if 'Tags' in ami_details:
        for tag in ami_details['Tags']:
            if tag['Key'] == 'Environment':
                tag['Value'] = new_environment_value
                break
        else:
            # If 'Environment' tag does not exist, add it
            ami_details['Tags'].append({'Key': 'Environment', 'Value': new_environment_value})
    else:
        # If 'Tags' does not exist, create it with the 'Environment' tag
        ami_details['Tags'] = [{'Key': 'Environment', 'Value': new_environment_value}]
    
    return ami_details

def copy_ami(args, ami_details, source_region, dest_region, dest_tfvars, dry_run=False):
    """
    Copy an AMI from one configuration to another using KMS keys defined in `.tfvars` files.

    Args:
    source_ami_id (str): The ID of the AMI to copy.
    source_region (str): The region where the source AMI is located.
    dest_region (str): The region to which the AMI will be copied.
    source_tfvars (str): Path to the source `.tfvars` file.
    dest_tfvars (str): Path to the destination `.tfvars` file.

    Returns:
    str: The ID of the copied AMI or a dry run message.
    """

    if args.debug: 
        print_debug(f"Variables being passed ami_details: {ami_details}, source_region:{source_region}, dest_region:{dest_region}, ")
    source_client = boto3.client('ec2', region_name=source_region)
    
    # Assuming you have defined read_kms_key_from_tfvars somewhere
    dest_kms_key_alias = read_kms_key_from_tfvars(dest_tfvars)
    kms_key = get_kms_key_arn_from_alias(args, dest_kms_key_alias, dest_region)
    if args.debug: 
        print_debug(f"dest_kms_key_alias is : {dest_kms_key_alias}")
    ami_details = update_environment_tag(ami_details, args.to_env)
    try:
        tag_specifications = [
            {
                'ResourceType': 'image',
                'Tags': ami_details['Tags']
            }
        ]
    
        response = source_client.copy_image(
            Name=f"{ami_details['Name']}-{args.to_env}",
            SourceImageId=ami_details['ImageId'],
            SourceRegion=source_region,
            Encrypted=True,
            KmsKeyId=kms_key,
            CopyImageTags=True,  
            DryRun=dry_run,
            TagSpecifications=tag_specifications
        )
        return response['ImageId'] if not dry_run else "Dry run successful, no AMI copied."
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            print_success(f"Dry run successful: {e}")
            return "Dry run successful, no AMI copied."
        else:
            print_error(f"Failed to copy AMI:  {e}")
            raise ValueError(f"{e}")
            traceback.print_exc()
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        traceback.print_exc()
        raise ValueError(f"{e}")




def read_ami_details_from_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)



def get_kms_key_arn_from_alias(args, alias_name, region_name='us-east-1'):
    """
    Get the KMS key ARN from an alias.

    Args:
    alias_name (str): The alias name of the KMS key.
    region_name (str): The AWS region where the KMS key is located. Default is 'us-east-1'.

    Returns:
    str: The ARN of the KMS key.
    """


    # print_info(f"Alias is : {alias_name}")
    # alias = run_shell_command(f"aws kms list-aliases --query 'Aliases['*']'")
    # print_info(f" return value : {alias}")
    # return True
    kms_client = boto3.client('kms', region_name=region_name)
    
    try:
        # List aliases and find the one that matches the provided alias name
        paginator = kms_client.get_paginator('list_aliases')
        for page in paginator.paginate():
            for alias in page['Aliases']:
                if alias['AliasName'] == f'alias/{alias_name}':
                    # Combine AliasArn and TargetKeyId to form the required output
                    if args.debug: 
                        print_debug(f"AliasArn:{alias['AliasArn']}")
                        print_debug(f"TargetKeyId : {alias['TargetKeyId']}")
                    # Split the AliasArn to get the base ARN (up to the account ID)
                    arn_parts = alias['AliasArn'].split(':')
                    # Replace 'alias' with 'key' and append the TargetKeyId
                    key_arn = ':'.join(arn_parts[:5]) + f":key/{alias['TargetKeyId']}"
                    print_info(f"ARN : {key_arn}")
                    return key_arn
        
        raise ValueError(f"Alias '{alias_name}' not found")
    except ClientError as e:
        print(f"Failed to get KMS key ARN: {e}")
        raise ValueError(f"{e}")
    
def copy_command(args): 
    try:
        fetch_config(args)  # This will now operate relative to the new working directory
        print_info("Configuration fetched successfully:")
        
        dest_tfvars, dest_file_location = find_tfvars_file(args.to_env, args)
        print_info("Getting source AMI id from file.")
        
            
        ami_details = read_ami_details_from_file(f'{args.build_directory}/source_ami_id.txt')
        source_region = os.getenv('AWS_DEFAULT_REGION')
        dest_region = os.getenv('AWS_DEST_REGION', source_region)
        account_id = extract_account_name_from_tfvars(args, dest_file_location[0])
        fetch_account_config(args,account_id)
        set_aws_creds(args, source=args.to_env)
        
        # Assuming source and destination can be the same or derived from the args/environment
        if args.debug:
            copied_ami_id = copy_ami(args, ami_details, source_region, dest_region, dest_file_location, False)
            print_success(f"AMI copied successfully: {copied_ami_id}")
        else: 
            copied_ami_id = copy_ami(args, ami_details, source_region, dest_region, dest_file_location)
            print_success(f"AMI copied successfully: {copied_ami_id}")
        return True 
    except Exception as e:
        print_error(f"Error during AMI copy: {e}")
        traceback.print_exc()
        raise
