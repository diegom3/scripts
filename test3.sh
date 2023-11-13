#!/bin/bash

# Set the filename
file="example_file.txt"

# Read the file line by line
while IFS= read -r line; do
  # Check if the line contains the array "provider"
  if [[ $line == *provider=* ]]; then
    # Extract the values of the provider array
    provider_values=$(echo "$line" | cut -d'=' -f2 | tr -d '[:space:]')

    # Define a key-value map for providers
    declare -A provider_map
    provider_map=(
      ["value1"]="mapped_value1"
      ["value2"]="mapped_value2"
      ["value3"]="mapped_value3"
      ["value4"]="mapped_value4"
    )

    # Split the comma-separated values into an array
    IFS=',' read -ra values_array <<< "$provider_values"

    # Iterate through the values and check against the map
    for value in "${values_array[@]}"; do
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
