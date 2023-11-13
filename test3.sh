#!/bin/bash

# Set the filename
file="example_file.txt"

# Read the file line by line
while IFS= read -r line; do
  # Check if the line contains the array declaration for "provider"
  if [[ $line == *"provider"*"("*")" ]]; then
    # Extract the values inside the array
    provider_values=($(echo "$line" | sed -n 's/.*provider=\(.*\))/\1/p' | tr -d '()'))

    # Define a key-value map for providers
    provider_map=("value1" "value2" "value3")

    # Iterate through the values in the "provider" array
    for value in "${provider_values[@]}"; do
      # Check if the value is in the provider_map
      if [[ " ${provider_map[@]} " =~ " $value " ]]; then
        # If a match is found, add it to another variable
        matched_provider="$value"
        break
      fi
    done
  fi
done < "$file"

# Display the matched provider value
echo "Matched provider value: $matched_provider"
