# Submit MCAP Samples
Python script to submit files to CIS Malicious Code Analysis Platform (powered by ThreatGrid) bulk sample submit API.

## Setup
Rename **sample-config.py** to **config.py** and add your API key.

## Usage
```
usage: python Submit_MCAP_Samples.py [-h] [-e] [-v] [-d] sample

Utility for uploading single or multiple files to the Malicious Code Analysis
Platform (MCAP) for processing and reporting.

positional arguments:
  sample         Sample file or directory

options:
  -h, --help     show this help message and exit
  -v, --verbose  Increase output verbosity
  -d, --debug    Enable debug mode for testing
```
---
MCAP information: https://mcap.cisecurity.org/about