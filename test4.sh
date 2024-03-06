#!/bin/bash

# Array of script names to check
script_names=("script1.sh" "script2.sh" "script3.sh")

# Remote repository URL
repo_url="https://github.com/your_username/your_repo"

# Local directory for storing scripts
local_dir="/path/to/local/directory"

# Local file to append the script contents
output_file="combined_scripts.sh"

# Loop through each script name in the array
for script_name in "${script_names[@]}"; do
    # Check if the script exists in the remote repository
    if curl -s --head "${repo_url}/${script_name}" | head -n 1 | grep "200 OK" > /dev/null; then
        # If script exists, append its contents to the local file
        echo "Appending ${script_name} to ${output_file}"
        curl -s "${repo_url}/${script_name}" >> "${local_dir}/${output_file}"
        echo "" >> "${local_dir}/${output_file}"  # Add newline after each script
    fi
done

echo "Script appending completed."
