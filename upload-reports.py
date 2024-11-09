import requests
import sys

file_name = sys.argv[1]
scan_type = ''

if file_name == 'gitleaks.json':
    scan_type = "Gitleaks Scan"
elif file_name == 'njsscan.sarif':
    scan_type = "SARIF"
elif file_name == 'semgrep.json':
    scan_type = 'Semgrep JSON Report'    


headers = {
    'Authorization': 'Token 5d9b9e650bcfdc45888b3e6da582ca621b4cefd1'
}

url = 'https://demo.defectdojo.org/api/v2/import-scan/'

data = {
    'active': True,
    'verified': True,
    'scan_type': scan_type,
    'minimum-severity': 'Low',
    'engagement': 19

}

files = {
    'file' : open(file_name, 'rb')
}

response = requests.post(url, headers=headers, data=data, files=files)

if response.status_code == 201:
    print("Scan results imported successfully")
else:
    print(f'Failed to import scan results : {response.content}')    