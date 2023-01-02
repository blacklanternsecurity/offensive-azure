# outsider_recon.py

This module is a port of many different cmdlets from [AADInternals](https://github.com/Gerenios/AADInternals). It only requires a domain to be supplied to run successfully. Enumerated information includes:

- Tenant OpenID configuration
- Domain login information
- Domain information
- Tenant ID extraction
- Other domains under the shared tenant

## Installation

```bash
git clone https://github.com/blacklanternsecurity/offensive-azure.git
cd ./offensive-azure/Outsider_Recon/
pipenv shell
pip install -r requirements.txt
```

## Usage

```bash
usage: outsider_recon.py <domain> [-o|--outfile <path-to-file>] [-u|--user <user>]

  =====================================================================================
  # This module will enumerate all available information for a given target domain    #
  # within an Azure tenant. This does not require any level of pre-existing access.   #
  =====================================================================================

positional arguments:
  domain                The target Microsoft/Azure domain

options:
  -h, --help            show this help message and exit
  -o <path>, --outfile-path <path>
                        (string) The path where you want the recon data (json object) saved. If not supplied, module defaults to the current directory
  -f <filename>, --filename <filename>
                        (string) The filename you want the recon data (json object) saved as.
  -sf, --single-file    (boolean) Whether or not to output all results to a single file. If not supplied, module defaults to False
  -s, --silent          (boolean) Whether or not to suppress all output to stdout. If not supplied, module
                        defaults to False
  -u <username>, --user <username>
                        (string) The user you want to use during enumeration. Do not include the domain. If not supplied, module defaults to "none"
```

## Examples

```bash
python3 outsider_recon.py domain.com -u user.name -o ./loot
```
