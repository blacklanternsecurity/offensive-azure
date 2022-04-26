# Azure AD

This set of modules are meant for targetting Azure AD data. Each module will output a set of data files for further analysis. Support is provided for bloodhound compatible data files in each module. Microsoft is deprecating the use of the Azure AD Graph API on June 30 2022. So, these modules are not going to use any of the now deprecated API calls. Rather, they will be using other available APIs including the currently supported Microsoft Graph API.

## get_groups.py

This module uses the Microsoft Graph API to request all groups present within Azure AD. It requires an ms_graph token or a refresh token to be supplied as an argument, or a refresh token supplied as an environment variable `REFRESH_TOKEN`. This module will output a condensed set of results to stdout. Additionally, the module will create three data files. One condensed data json file, one raw json output file, and one file compatible for use with BloodHound.

## get_users.py

This module uses the Microsoft Graph API to request all users present within Azure AD. It requires an ms_graph token or a refresh token to be supplied as an argument, or a refresh token supplied as an environment varialbe `REFRESH_TOKEN`. This module will output a condensed set of results to stdout. Additionally, the module will create three data files. One condensed data json file, one raw json output file, and one file compatible for use with BloodHound.

The module attempts to pull all available properties as defined in the Microsoft Graph documentation, not just the default properties.

## get_tenant.py

This module uses a combination of access token and public endpoints to gather the tenant ID and tenant name (Federation Brand Name). It requires that an access token or a refresh token is supplied as arguments. If neither are supplied, the module will also check for the `REFRESH_TOKEN` variable and use it to request a valid access token.

The module will output two data files. One text file containing the tenant ID and tenant name. Second a JSON file compatible for use with BloodHound.

## Installation

```bash
git clone https://github.com/blacklanternsecurity/offensive-azure.git
cd ./offensive-azure/Azure_AD/
pipenv shell
pip install -r requirements.txt
```

## get_groups Usage

```bash
usage: get_groups.py [-t|--graph_token <graph_token>] [-r|--refresh_token <refresh_token>]

        ==========================================================
        #                                                        #
        #  Uses the Microsoft Graph API to pull a full list of   #
        #  group details.                                        #
        #                                                        #
        #  If no ms_graph token or refresh_token is supplied,    #
        #  module will look in the REFRESH_TOKEN environment     #
        #  variable and request the ms_graph token               #
        #                                                        #
        #  Outputs condensed results in a text file, a raw json  #
        #  output file, and a json file compatible with          #
        #  BloodHound                                            #
        #                                                        #
        ==========================================================

optional arguments:
  -h, --help            show this help message and exit
  -t <graph_token>, --graph_token <graph_token>
                        The ms_graph token you would like to use
  -r <refresh_token>, --refresh_token <refresh_token>
                        The refresh token you would like to use
  -R <refresh_token_file>, --refresh_token_file <refresh_token_file>
                        A JSON file saved from token_juggle.py containing the refresh token you would like to use.
  -o <path>, --outfile_path <path>
                        The path of where you want the group data saved. If not supplied, module defaults to the current directory.
```

## get_users Usage

```bash
usage: get_users.py [-t|--graph_token <graph_token>] [-r|--refresh_token <refresh_token>]

        ==========================================================
        #                                                        #
        #  Uses the Microsoft Graph API to pull a full list of   #
        #  user details.                                         #
        #                                                        #
        #  If no ms_graph token or refresh_token is supplied,    #
        #  module will look in the REFRESH_TOKEN environment     #
        #  variable and request the ms_graph token               #
        #                                                        #
        #  Outputs condensed results in a text file, a raw json  #
        #  output file, and a json file compatible with          #
        #  BloodHound                                            #
        #                                                        #
        ==========================================================

optional arguments:
  -h, --help            show this help message and exit
  -t <graph_token>, --graph_token <graph_token>
                        The ms_graph token you would like to use
  -r <refresh_token>, --refresh_token <refresh_token>
                        The refresh token you would like to use
  -R <refresh_token_file>, --refresh_token_file <refresh_token_file>
                        A JSON file saved from token_juggle.py containing the refresh token you would like to use.
  -o <path>, --outfile_path <path>
                        The path of where you want the user data saved. If not supplied, module defaults to the current directory.
```

## get_tenant Usage

```bash
usage: get_tenant.py [-t|--access_token <access_token>] [-r|--refresh_token <refresh_token>]

        ==========================================================
        #                                                        #
        #  If no access token or refresh_token is supplied,      #
        #  module will look in the REFRESH_TOKEN environment     #
        #  variable and request an access token                  #
        #                                                        #
        #  Outputs results in a text file, and a json file       #
        #  compatible with BloodHound                            #
        #                                                        #
        ==========================================================

optional arguments:
  -h, --help            show this help message and exit
  -t <access_token>, --access_token <access_token>
                        The access token you would like to use
  -r <refresh_token>, --refresh_token <refresh_token>
                        The refresh token you would like to use
  -R <refresh_token_file>, --refresh_token_file <refresh_token_file>
                        A JSON file saved from token_juggle.py containing the refresh token you would like to use.
  -o <path>, --outfile_path <path>
                        The path of where you want the tenant data saved. If not supplied, module defaults to the current directory.
```