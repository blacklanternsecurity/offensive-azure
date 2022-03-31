# outsider-recon.py

This module is a port of many different cmdlets from [AADInternals](https://github.com/Gerenios/AADInternals). It only requires a domain to be supplied to run successfully. Enumerated information includes:

- tenant OpenID configuration
- domain login information
- domain information
- tenant id extraction
- other domains under the shared tenant

## Usage

```bash
usage: outsider-recon.py <domain> [-o|--outfile <path-to-file>] [-u|--user <user>]

  =====================================================================================
  # This module will enumerate all available information for a given target domain    #
  # within an Azure tenant. This does not require any level of pre-existing access.   #
  =====================================================================================

positional arguments:
  domain                The target Microsoft/Azure domain

optional arguments:
  -h, --help            show this help message and exit
  -o <path>, --outfile-path <path>
                        (string) The path where you want the recon data (json object) saved. If not supplied, module defaults to the
                        current directory
  -u <username>, --user <username>
                        (string) The user you want to use during enumeration. Do not include the domain. If not supplied, module defaults
                        to "none"
```

## Examples

```bash
python3 outsider-recon.py domain.com -u user.name -o ./loot
```
