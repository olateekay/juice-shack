# Need an API key to authenticate to DefectDojo and access its API - defectdojo.org/api

import requests

# HTTP Authorization Request Header = used to provide credentials that authenticate a user agent with a server 

# For best practice - we should reset the api token as an environment variable
headers = {
    'Authorization': 'Token 708c0fcec6982bd5e4c2c7832c28c23b450ad8e0'
}

import os

# URL for the DefectDojo API endpoint
url = 'http://192.168.172.210:8080/api/v2/import-scan/'

# Define multiple scan configurations
data = [
    {
        'scan_type': 'SARIF',
        'file': open('njsscan.sarif', 'rb'),
        'active': True,
        'verified': True,
        'minimum_severity': 'Low',
        'engagement': 2
    },
    {
        'scan_type': 'Semgrep JSON Report',
        'file': open('semgrep.json', 'rb'),
        'active': True,
        'verified': True,
        'minimum_severity': 'Low',  
        'engagement': 2  
    },
    {
        'scan_type': 'Gitleaks Scan',
        'file': open('gitleaks.json', 'rb'),
        'active': True,
        'verified': True,
        'minimum_severity': 'Low', 
        'engagement': 2  
    }
]

# You can then iterate through each config to send the files
for config in data:
    files = {'file': config['file']}
    request_data = {
        'scan_type': config['scan_type'],
        'active': config['active'],
        'verified': config['verified'],
        'minimum_severity': config['minimum_severity'],
        'engagement': config['engagement']
    }
    
    # Check the response from the server
    response = requests.post(url, headers=headers, files=files, data=request_data)
    if response.status_code == 201: # API documentation shows 201 status code as successful
        print('Upload successful:', response.json())
    else:
        print('Upload failed:', response.status_code, response.text)
    
    # Close the file immediately after upload
    config['file'].close()
