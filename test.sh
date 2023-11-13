#!/bin/bash

# Set the filename
file="your_file.txt"

# Define a map of providers and their corresponding values
provider_map=("value1" "value2" "value3")

# Initialize the variable to store the matched provider values
matched_providers=""

# Read the file line by line
while IFS= read -r line; do
  # Check if the line contains the string "provider"
  if [[ $line == *provider* ]]; then
    # Extract the key and value from the line
    key=$(echo "$line" | awk -F'=' '{print $1}' | tr -d '[:space:]')
    value=$(echo "$line" | awk -F'=' '{print $2}' | tr -d '[:space:]')

    # Check if the key is "provider" and the value is in the provider_map
    if [ "$key" == "provider" ]; then
      for map_value in "${provider_map[@]}"; do
        if [ "$value" == "$map_value" ]; then
          # If a match is found, add it to the variable
          matched_providers+=" $value"
          break
        fi
      done
    fi
  fi
done < "$file"

# Display the matched provider values
echo "Matched provider values: $matched_providers"
