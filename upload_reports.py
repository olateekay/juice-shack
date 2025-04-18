import requests
import sys
import os

# Upload a security‑scan report to OWASP DefectDojo.
# The script is called by the GitLab job `upload_reports` and expects one
# argument: the filename of the report to send (gitleaks.json, semgrep.json, or
# njsscan.sarif).

# Get the file name from command‑line argument
file_name = sys.argv[1]

# Pull API key from environment variable (set in GitLab CI settings)
api_token = os.environ.get('DEFECTDOJO_API_KEY')
if not api_token:
    print("DEFECTDOJO_API_KEY variable not set.")
    sys.exit(1)

# Prep the auth header
headers = {
    'Authorization': f'Token {api_token}'
}

dojo_url = os.environ.get("DOJO_URL", "").rstrip("/")       # Get DOJO_URL env var, default empty string "" if not set, remove any trailing slash '/' with .rstrip
if not dojo_url:
    print("DOJO_URL not set.")
    sys.exit(1)
# DefectDojo API endpoint

# FIX: replaced hardcoded url with environment variable
url = f"{dojo_url}/api/v2/import-scan/"

# Map filename -> scan_type recognized by DefectDojo
if file_name == 'gitleaks.json':
    scan_type = 'Gitleaks Scan'
elif file_name == 'semgrep.json':
    scan_type = 'Semgrep JSON Report'
elif file_name == 'njsscan.sarif':
    scan_type = 'SARIF'
else:
    print(f"Unknown file type: {file_name}")
    sys.exit(1)

# Basic payload – engagement 2 is a fixed test engagement in our Dojo instance
data = {
    'scan_type': scan_type,
    'active': True,
    'verified': True,
    'minimum_severity': 'Low',
    'engagement': 2             # replace with specific engagement ID as needed
}

# Open the report file in binary mode and POST it
files = {
    'file': open(file_name, 'rb')
}

response = requests.post(url, headers=headers, data=data, files=files)

# Evaluate response
if response.status_code == 201:     # DefectDojo documentation says 201 is the success response status code
    print('Scan uploaded successfully.')
else:
    print('Failed to upload scan. Status code:', response.status_code)
    print('Response:', response.content)
