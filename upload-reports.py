import requests

headers = {
    'Authorization': 'Token 5d9b9e650bcfdc45888b3e6da582ca621b4cefd1'
}

url = 'https://demo.defectdojo.org/api/v2/import-scan/'

data = {
    'active': True,
    'verified': True,
    'scan-type': 'Gitleaks Scan',
    'minimum-severity': 'Low',
    'engagement': 19

}

files = {
    'file' : open('gitleaks.json', 'rb')
}

response = requests.post(url, headers=headers, data=data, files=files)

if response.status_code == 201:
    print("Scan results imported successfully")
else:
    print('Failed to import scan results : {response.content}')    