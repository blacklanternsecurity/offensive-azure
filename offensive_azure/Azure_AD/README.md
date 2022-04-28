# Azure AD

This set of modules are meant for targetting Azure AD data. Each module will output a set of data files for further analysis. Support is provided for bloodhound compatible data files in each module. Microsoft is deprecating the use of the Azure AD Graph API on June 30 2022. So, these modules are not going to use any of the now deprecated API calls. Rather, they will be using other available APIs including the currently supported Microsoft Graph API.

## General Functionality

Each of these modules will output a set of files. All include a raw json response file and a bloodhound compatible json file. Some include a condensed json output file. Usage of these modules is flexible. You may supply the required access token, or a refresh token via script arguments. You may also define an envrionment variable that contains a refresh token. This is the recommended way, and each module will handle the token requests to get the appropriate access token type.

## Installation

```bash
git clone https://github.com/blacklanternsecurity/offensive-azure.git
cd ./offensive-azure/Azure_AD/
pipenv shell
pip install -r requirements.txt
```

## get_vms Usage

```bash
usage: get_vms.py [-t|--arm_token <arm_token>] [-r|--refresh_token <refresh_token>]

        ==========================================================
        #                                                        #
        #  Uses Azure Resource Management API to pull a full     #
        #  list of virtual machines.                             #
        #                                                        #
        #  If no ARM token or refresh_token is supplied,         #
        #  module will look in the REFRESH_TOKEN environment     #
        #  variable and request the ARM token                    #
        #                                                        #
        #  Outputs a raw json output file, and a json file       #
        #  compatible with BloodHound                            #
        #                                                        #
        ==========================================================

optional arguments:
  -h, --help            show this help message and exit
  -t <arm_token>, --arm_token <arm_token>
                        The ARM token you would like to use
  -r <refresh_token>, --refresh_token <refresh_token>
                        The refresh token you would like to use
  -R <refresh_token_file>, --refresh_token_file <refresh_token_file>
                        A JSON file saved from token_juggle.py containing the refresh token you would like to use.
  -o <path>, --outfile_path <path>
                        The path of where you want the virtual machine data saved. If not supplied, module defaults to the current directory.
```

## get_resource_groups Usage

```bash
usage: get_resource_groups.py [-t|--arm_token <arm_token>] [-r|--refresh_token <refresh_token>]

        ==========================================================
        #                                                        #
        #  Uses Azure Resource Management API to pull a full     #
        #  list of resource groups.                              #
        #                                                        #
        #  If no ARM token or refresh_token is supplied,         #
        #  module will look in the REFRESH_TOKEN environment     #
        #  variable and request the ARM token                    #
        #                                                        #
        #  Outputs a raw json output file, and a json file       #
        #  compatible with BloodHound                            #
        #                                                        #
        ==========================================================

optional arguments:
  -h, --help            show this help message and exit
  -t <arm_token>, --arm_token <arm_token>
                        The ARM token you would like to use
  -r <refresh_token>, --refresh_token <refresh_token>
                        The refresh token you would like to use
  -R <refresh_token_file>, --refresh_token_file <refresh_token_file>
                        A JSON file saved from token_juggle.py containing the refresh token you would like to use.
  -o <path>, --outfile_path <path>
                        The path of where you want the resource group data saved. If not supplied, module defaults to the current directory.
```

## get_subscriptions Usage

```bash
usage: get_subscriptions.py [-t|--arm_token <arm_token>] [-r|--refresh_token <refresh_token>]

        ==========================================================
        #                                                        #
        #  Uses Azure Resource Management API to pull a full     #
        #  list of subscriptions.                                #
        #                                                        #
        #  If no ARM token or refresh_token is supplied,    #
        #  module will look in the REFRESH_TOKEN environment     #
        #  variable and request the ARM token                    #
        #                                                        #
        #  Outputs condensed results in a text file, a raw json  #
        #  output file, and a json file compatible with          #
        #  BloodHound                                            #
        #                                                        #
        ==========================================================

optional arguments:
  -h, --help            show this help message and exit
  -t <arm_token>, --arm_token <arm_token>
                        The ARM token you would like to use
  -r <refresh_token>, --refresh_token <refresh_token>
                        The refresh token you would like to use
  -R <refresh_token_file>, --refresh_token_file <refresh_token_file>
                        A JSON file saved from token_juggle.py containing the refresh token you would like to use.
  -o <path>, --outfile_path <path>
                        The path of where you want the subscription data saved. If not supplied, module defaults to the current directory.
```

## get_group_members Usage

```bash
usage: get_group_members.py [-t|--graph_token <graph_token>] [-r|--refresh_token <refresh_token>]

        ==========================================================
        #                                                        #
        #  Uses the Microsoft Graph API to pull a full list of   #
        #  user group membership details.                        #
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
                        The path of where you want the group membership data saved. If not supplied, module defaults to the current directory.
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