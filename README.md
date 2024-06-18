# Nessus API exporter

This script exports all Nessus scans to .nessus files using the Nessus API.

## Usage
```sh
python3 nessus_export.py <username> <password> <Nessus URL> --output path/to/output
```

The default export path is "./export". This script will also recreate all folder structure from Nessus in the filesystem