#!/bin/bash

# Set the filename
file="your_file.sh"  # Replace with your actual filename

# Read the file line by line
while IFS= read -r line; do
  # Check if the line contains the array definition for "provider"
  if [[ $line == *"provider=("* ]]; then
    # Extract the values of the provider array
    provider_values=$(echo "$line" | sed -n 's/.*provider=//p' | tr -d '() ')
    
    # Convert the space-separated values into an array
    IFS=' ' read -r -a provider_array <<< "$provider_values"

    # Define a map of providers and their corresponding values
    provider_map=("value1" "value2" "value3")

    # Loop through the values in the provider array
    for value in "${provider_array[@]}"; do
      # Check if the value is in the provider_map
      if [[ " ${provider_map[*]} " == *" $value "* ]]; then
        # If a match is found, add it to another variable
        matched_provider="$value"
        break
      fi
    done
  fi
done < "$file"

# Display the matched provider value
echo "Matched provider value: $matched_provider"
