<p align="center">
  <img src="https://user-images.githubusercontent.com/28767257/160513484-cb70370c-9fce-48d1-84ec-8b9ea3cf8e5a.png">
</p>

[![Python Version](https://img.shields.io/pypi/pyversions/offensive_azure?style=plastic)](https://www.python.org) [![Build Status](https://img.shields.io/github/workflow/status/blacklanternsecurity/offensive-azure/Pylint?style=plastic)](https://github.com/blacklanternsecurity/offensive-azure/actions/workflows/pylint.yml?query=workflow%3Apylint)

Collection of offensive tools targeting Microsoft Azure written in Python to be platform agnostic. The current list of tools can be found below with a brief description of their functionality.

- [`./Device_Code/device_code_easy_mode.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Device_Code)
  - Generates a code to be entered by the target user
  - Can be used for general token generation or during a phishing/social engineering campaign.
- [`./Access_Tokens/token_juggle.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Access_Tokens)
  - Takes in a refresh token in various ways and retrieves a new refresh token and an access token for the resource specified
- [`./Access_Tokens/read_token.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Access_Tokens)
  - Takes in an access token and parses the included claims information, checks for expiration, attempts to validate signature
- [`./Outsider_Recon/outsider_recon.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Outsider_Recon)
  - Takes in a domain and enumerates as much information as possible about the tenant without requiring authentication 
- [`./User_Enum/user_enum.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/User_Enum)
  - Takes in a username or list of usernames and attempts to enumerate valid accounts using one of three methods
  - Can also be used to perform a password spray
- [`./Azure_AD/get_tenant.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Azure_AD)
  - Takes in an access token or refresh token, outputs tenant ID and tenant Name
  - Creates text output file as well as BloodHound compatible aztenant file
- [`./Azure_AD/get_users.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Azure_AD)
  - Takes in an access token or refresh token, outputs all users in Azure AD and all available user properties in Microsoft Graph
  - Creates three data files, a condensed json file, a raw json file, and a BloodHound compatible azusers file

# Installation

Offensive Azure can be installed in a number of ways or not at all. 

You are welcome to clone the repository and execute the specific scripts you want. A `requirements.txt` file is included for each module to make this as easy as possible.

## Poetry

The project is built to work with `poetry`. To use, follow the next few steps:

```
git clone https://github.com/blacklanternsecurity/offensive-azure.git
cd ./offensive-azure
poetry install
```

## Pip

The packaged version of the repo is also kept on pypi so you can use `pip` to install as well. We recommend you use `pipenv` to keep your environment as clean as possible.

```
pipenv shell
pip install offensive_azure
```

# Usage

It is up to you for how you wish to use this toolkit. Each module can be ran independently, or you can install it as a package and use it in that way. Each module is exported to a script named the same as the module file. For example:

## Poetry

```
poetry install
poetry run outsider_recon your-domain.com
```

## Pip

```
pipenv shell
pip install offensive_azure
outsider_recon your-domain.com
```
