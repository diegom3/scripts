#!/bin/bash

# Set the filename
file="example_file.txt"

# Read the file line by line
while IFS= read -r line; do
  # Check if the line contains the array named "provider"
  if [[ $line == *provider* ]]; then
    # Extract the values from the array
    provider_values=$(echo "$line" | grep -oP '\(.*\)' | tr -d '()' | tr -d '"' | tr -s ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    # Convert the space-separated values to an array
    IFS=" " read -r -a provider_array <<< "$provider_values"

    # Define a key-value map
    declare -A provider_map
    provider_map=([value1]="mapped_value1" [value2]="mapped_value2" [value3]="mapped_value3")

    # Check if the values in the provider array match the key-value map
    for value in "${provider_array[@]}"; do
      mapped_value="${provider_map[$value]}"
      if [ -n "$mapped_value" ]; then
        # If a match is found, add it to another variable
        matched_provider="$mapped_value"
        break
      fi
    done
  fi
done < "$file"

# Display the matched provider value
echo "Matched provider value: $matched_provider"
