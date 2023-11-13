#!/bin/bash

# Set the filename
file="your_file.txt"

# Read the file line by line
while IFS= read -r line; do
  # Check if the line contains the array named "provider"
  if [[ $line == *provider=* ]]; then
    # Extract the values of the provider array
    provider_values=$(echo "$line" | awk -F'=' '{print $2}' | tr -d '[:space:]')
    
    # Define a key-value map for providers
    provider_map=("value1" "mapped_value1" "value2" "mapped_value2" "value3" "mapped_value3")

    # Split the comma-separated values into an array
    IFS=',' read -ra values_array <<< "$provider_values"

    # Iterate through the values array and append the mapped values
    for value in "${values_array[@]}"; do
      # Search for the value in the provider map and append the corresponding mapped value
      for ((i = 0; i < ${#provider_map[@]}; i+=2)); do
        if [ "$value" == "${provider_map[i]}" ]; then
          matched_provider_values+=("${provider_map[i+1]}")
          break
        fi
      done
    done
  fi
done < "$file"

# Display the matched provider values
echo "Matched provider values: ${matched_provider_values[@]}"

    provider_values=$(echo "$line" | sed -n 's/.*provider=("\(.*\)").*/\1/p' | tr -d '", ')
    provider_values=$(echo "$line" | grep -oP '\(.*\)' | tr -d '()')
    provider_values=$(echo "$line" | grep -oP '\(["'\'']*[^"'\'']*[,"'\'']*\)')
    provider_values=$(echo "$line" | grep -oP '\[.*\]' | tr -d '[:space:][]')
    provider_values=$(echo "$line" | awk -F'[()]' '{print $2}' | tr -d '[:space:]')

