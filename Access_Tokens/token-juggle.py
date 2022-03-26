#!/usr/bin/python3

'''
Copyright (C) 2022 Cody Martin BLSOPS LLC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

# pip3 install requests
# pip3 install argparse
# pip3 install colorama

import os, requests, sys, argparse, colorama, time, json

# Set up our colors
colorama.init()
success = colorama.Fore.GREEN
danger = colorama.Fore.RED
warning = colorama.Fore.YELLOW
reset = colorama.Style.RESET_ALL

# Setup argparse stuff
resource_choices = [
	'win_core_management',
	'azure_management',
	'graph',
	'ms_graph',
	'ms_manage',
	'teams',
	'office_apps',
	'office_manage',
	'outlook',
	'substrate'
]

description = '''
  =====================================================================================
  # Requests a new access token for a Microsoft/Azure resource using a refresh token. #
  #                                                                                   #
  # This script will attempt to load a refresh token from a REFRESH_TOKEN             #
  # environment variable if none is passed with '-r' or '-R'.                         #
  =====================================================================================
'''

arg_parser = argparse.ArgumentParser(prog='token-juggle.py', 
				     usage=success + '%(prog)s' + warning + ' <resource> ' + reset +'[-r \'refresh_token\' | -R \'./path/to/refresh_token.json\']', 
				     description=description,
			             formatter_class=argparse.RawDescriptionHelpFormatter)
arg_parser.add_argument('Resource',
			metavar='resource',
			type=str,
			help='The target Microsoft/Azure resource.\nChoose from the following: ' + str(resource_choices).replace('\'', '').replace('[','').replace(']',''),
			choices=resource_choices)
arg_parser.add_argument('-r',
			'--refresh_token',
			metavar='<refresh_token>',
			dest='refresh_token',
			type=str,
			help='(string) The refresh token you would like to use.',
			required=False)
arg_parser.add_argument('-R',
			'--refresh_token_file',
			metavar='<refresh_token_file>',
			dest='refresh_token_file',
			type=str,
			help='(string) A JSON file saved from this script containing the refresh token you would like to use.',
			required=False)
arg_parser.add_argument('-o',
			'--outfile',
			metavar='<filename>',
			dest='outfile_path',
			type=str,
			help='(string) The path/filename of where you want the new token data (json object) saved.\nIf not supplied, script defaults to "./YYYY-MM-DD_HH-MM-SS_<resource>_token.json"',
			required=False)

args = arg_parser.parse_args()

# Set a default outfile if none is given
outfile = args.outfile_path
if outfile == None:
	outfile = time.strftime('%Y-%m-%d_%H-%M-%S_' + args.Resource + '_token.json')

# Resources
win_core_management = 'https://management.core.windows.net'	# Windows Core Management
azure_management = 'https://management.azure.com'	# Azure Management (For use in Az [powershell, will not access AzAD cmdlets without also supplying graph token])
graph = 'https://graph.windows.net'	# Graph (For use with Az/AzureAD/AADInternals)
ms_graph = 'https://graph.microsoft.com'	# Microsoft Graph (Microsoft is moving towards this from graph in 2022)
ms_manage = 'https://enrollment.manage.microsoft.com' # Microsoft Manage
teams = 'https://api.spaces.skype.com' # Microsoft Teams
office_apps = 'https://officeapps.live.com' # Microsoft Office Apps
office_manage = 'https://manage.office.com' # Microsoft Office Management
outlook = 'https://outlook.office365.com' # Microsoft Outlook
substrate = 'https://substrate.office.com' # Substrate

# User agent to use with requests
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0' # Firefox User Agent

# Initializing
refresh_token = ''
client_id = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

# Set our resource based on position argument
if args.Resource == 'win_core_management':
	resource = win_core_management
elif args.Resource == 'azure_management':
	resource = azure_management
elif args.Resource == 'graph':
	resource = graph
elif args.Resource == 'ms_graph':
	resource = ms_graph
elif args.Resource == 'ms_manage':
	resource = ms_manage
elif args.Resource == 'teams':
	resource = teams
elif args.Resource == 'office_apps':
	resource = office_apps
elif args.Resource == 'office_manage':
	resource = office_manage
elif args.Resource == 'outlook':
	resource = outlook
elif args.Resource == 'substrate':
	resource = substrate
else:
	print(danger, '\nYou provided in invalid resource name.')
	print(reset)
	arg_parser.print_help()
	sys.exit()

# Check to see if any refresh token is given in the arguments
# If both are given, will use -r
# If no arguments are given, will look in the REFRESH_TOKEN environment variable
if args.refresh_token == None and args.refresh_token_file == None:
	try:
		refresh_token = os.environ['REFRESH_TOKEN']
	except KeyError as ke:
		print(danger, '\n\tNo refresh token found.\n', reset)
		arg_parser.print_help()
		sys.exit()
elif args.refresh_token == None:
	path = args.refresh_token_file
	try:
		json_file = open(path)
		json_file_data = json.load(json_file)
		json_file.close()
	except Exception as e:
		print(str(e))
		sys.exit()
	refresh_token = json_file_data['refresh_token']
else:
	refresh_token = args.refresh_token

# Setting up our post request
headers = {
	'User-Agent': user_agent
}

data = {
	'client_id': client_id,
	'grant_type': 'refresh_token',
	'scope': "openid",
	'resource': resource,
	'refresh_token': refresh_token
}

uri = 'https://login.microsoftonline.com/Common/oauth2/token'

# Sending the request
try:
	response = requests.post(uri, data=data, headers=headers)
	json_data = response.json()
	response.raise_for_status()
except requests.exceptions.HTTPError as he:
	print(danger)
	print(json_data['error'])
	print(json_data['error_description'])
	print(reset)
	sys.exit()

# Write the new token data to file
f = open(outfile, 'w+')
f.write(json.dumps(json_data))
f.close()

# Show the user the requested access and refresh tokens
print(success + 'Resource:\n' + reset + json_data['resource'] + '\n')
print(success + 'Access Token:\n' + reset + json_data['access_token'] + '\n')
print(success + 'Refresh Token:\n' + reset + json_data['refresh_token'] + '\n')

# Calculate the expired time
expires = json_data['expires_on']
print(success + 'Expires On:\n' + reset + time.ctime(int(expires)))
