node {
    // Assuming the environment variables are already set in your environment
    def webhookPayload = env.WEBHOOK_PAYLOAD
    def gitRef = env.GIT_REF
    def repoUrl = env.REPO_URL
    def prBranchName = env.PR_BRANCH_NAME
    def mergeBranch = env.MERGE_BRANCH

    // Define the JSON file and API endpoint
    def jsonFile = "data.json"
    def apiUrl = "https://your-api-endpoint.com/webhook"

    // Execute the Bash commands inside the Groovy script
    sh """
    #!/bin/bash

    # Create a JSON file from environment variables
    cat <<EOF > ${jsonFile}
    {
      "webhook_payload": "${webhookPayload}",
      "git_ref": "${gitRef}",
      "repo_url": "${repoUrl}",
      "pr_branch_name": "${prBranchName}",
      "merge_branch": "${mergeBranch}"
    }
    EOF

    echo "JSON file created: ${jsonFile}"

    # Post the JSON file to the API
    response=\$(curl -s -X POST -H "Content-Type: application/json" -d @${jsonFile} ${apiUrl})

    # Output the response from the API
    echo "Response from API: \$response"
    """
}
