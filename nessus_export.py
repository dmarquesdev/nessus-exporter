#!/usr/bin/env python3

import argparse
import requests
import os
import urllib3
from tqdm import tqdm

# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def login(username, password, url):
    print("Logging in...")
    login_url = f"{url}/session"
    payload = {'username': username, 'password': password}
    response = requests.post(login_url, json=payload, verify=False)
    response.raise_for_status()
    print("Login successful.")
    return response.json()['token']

def get_folders(token, url):
    print("Retrieving folders...")
    headers = {'X-Cookie': f'token={token}'}
    folders_url = f"{url}/folders"
    response = requests.get(folders_url, headers=headers, verify=False)
    response.raise_for_status()
    print("Folders retrieved.")
    return response.json()['folders']

def get_scans(token, url):
    print("Retrieving scans...")
    headers = {'X-Cookie': f'token={token}'}
    scans_url = f"{url}/scans"
    response = requests.get(scans_url, headers=headers, verify=False)
    response.raise_for_status()
    print("Scans retrieved.")
    return response.json()['scans']

def export_scan(token, url, scan_id, scan_name):
    print(f"Exporting scan '{scan_name}'...")
    headers = {'X-Cookie': f'token={token}'}
    export_url = f"{url}/scans/{scan_id}/export"
    payload = {'format': 'nessus'}
    response = requests.post(export_url, headers=headers, json=payload, verify=False)
    response.raise_for_status()
    file_id = response.json()['file']
    
    while True:
        status_url = f"{url}/scans/{scan_id}/export/{file_id}/status"
        response = requests.get(status_url, headers=headers, verify=False)
        response.raise_for_status()
        if response.json()['status'] == 'ready':
            break

    download_url = f"{url}/scans/{scan_id}/export/{file_id}/download"
    response = requests.get(download_url, headers=headers, stream=True, verify=False)
    response.raise_for_status()
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024
    t = tqdm(total=total_size, unit='iB', unit_scale=True, unit_divisor=1024, desc=f"Downloading {scan_name}", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [speed: {rate_fmt}]")
    content = b""
    for data in response.iter_content(block_size):
        t.update(len(data))
        content += data
    t.close()
    print(f"Scan '{scan_name}' exported.")
    return content

def save_scan_to_file(content, filepath):
    print(f"Saving scan to '{filepath}'...")
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'wb') as f:
        f.write(content)
    print(f"Scan saved to '{filepath}'.")

def main(username, password, url, output_folder):
    try:
        token = login(username, password, url)
        folders = get_folders(token, url)
        scans = get_scans(token, url)
        
        folder_map = {folder['id']: folder['name'] for folder in folders}
        
        for scan in scans:
            folder_name = folder_map.get(scan['folder_id'], 'Default Folder')
            scan_name = scan['name']
            scan_id = scan['id']
            
            file_content = export_scan(token, url, scan_id, scan_name)
            filepath = os.path.join(output_folder, folder_name, f"{scan_name}.nessus")
            
            save_scan_to_file(file_content, filepath)
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting...")
        exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Export Nessus scans to .nessus files')
    parser.add_argument('username', help='Nessus username')
    parser.add_argument('password', help='Nessus password')
    parser.add_argument('url', help='Nessus URL')
    parser.add_argument('--output', default='export', help='Output folder for the exported scans')
    
    args = parser.parse_args()
    main(args.username, args.password, args.url, args.output_folder)