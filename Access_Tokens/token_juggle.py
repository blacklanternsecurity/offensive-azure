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

import os
import sys
import argparse
import time
import json
import requests
import colorama


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
	'substrate',
	'm365_admin'
]

DESCRIPTION = '''
	=====================================================================================
	# Requests a new access token for a Microsoft/Azure resource using a refresh token. #
	#                                                                                   #
	# This script will attempt to load a refresh token from a REFRESH_TOKEN             #
	# environment variable if none is passed with '-r' or '-R'.                         #
	=====================================================================================
'''

arg_parser = argparse.ArgumentParser(prog='token_juggle.py',
				usage=success + '%(prog)s' + warning + ' <resource> ' + \
				reset +'[-r \'refresh_token\' | -R \'./path/to/refresh_token.json\']',
				description=DESCRIPTION,
				formatter_class=argparse.RawDescriptionHelpFormatter)
arg_parser.add_argument('Resource',
			metavar='resource',
			type=str,
			help='The target Microsoft/Azure resource.\nChoose from the following: ' + \
				str(resource_choices).replace('\'', '').replace('[','').replace(']',''),
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
			help='(string) A JSON file saved from this script ' \
				'containing the refresh token you would like to use.',
			required=False)
arg_parser.add_argument('-o',
			'--outfile',
			metavar='<filename>',
			dest='outfile_path',
			type=str,
			help='(string) The path/filename of where you want '\
				'the new token data (json object) saved.'\
				'\nIf not supplied, script defaults to '\
				'"./YYYY-MM-DD_HH-MM-SS_<resource>_token.json"',
			required=False)

args = arg_parser.parse_args()

# Set a default outfile if none is given
outfile = args.outfile_path
if outfile is None:
	outfile = time.strftime('%Y-%m-%d_%H-%M-%S_' + args.Resource + '_token.json')

# Resources

# Windows Core Management
WIN_CORE_MANAGEMENT = 'https://management.core.windows.net'

# Azure Management 
	# (For use in Az [powershell-will not access AzAD cmdlets without also supplying graph token])
AZURE_MANAGEMENT = 'https://management.azure.com'

# Graph (For use with Az/AzureAD/AADInternals)
GRAPH = 'https://graph.windows.net'

# Microsoft Graph (Microsoft is moving towards this from graph in 2022)
MS_GRAPH = 'https://graph.microsoft.com'

# Microsoft Manage
MS_MANAGE = 'https://enrollment.manage.microsoft.com'

# Microsoft Teams
TEAMS = 'https://api.spaces.skype.com'

# Microsoft Office Apps
OFFICE_APPS = 'https://officeapps.live.com'

# Microsoft Office Management
OFFICE_MANAGE = 'https://manage.office.com'

# Microsoft Outlook
OUTLOOK = 'https://outlook.office365.com'

# Substrate
SUBSTRATE = 'https://substrate.office.com'

# Microsoft 365 Admin Center
M365_ADMIN = 'https://admin.microsoft.com'

# User agent to use with requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0'

# Initializing
REFRESH_TOKEN = ''
CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

# Set our resource based on position argument
if args.Resource == 'win_core_management':
	RESOURCE = WIN_CORE_MANAGEMENT
elif args.Resource == 'azure_management':
	RESOURCE = AZURE_MANAGEMENT
elif args.Resource == 'graph':
	RESOURCE = GRAPH
elif args.Resource == 'ms_graph':
	RESOURCE = MS_GRAPH
elif args.Resource == 'ms_manage':
	RESOURCE = MS_MANAGE
elif args.Resource == 'teams':
	RESOURCE = TEAMS
elif args.Resource == 'office_apps':
	RESOURCE = OFFICE_APPS
elif args.Resource == 'office_manage':
	RESOURCE = OFFICE_MANAGE
elif args.Resource == 'outlook':
	RESOURCE = OUTLOOK
elif args.Resource == 'substrate':
	RESOURCE = SUBSTRATE
elif args.Resource == 'm365_admin':
	RESOURCE = M365_ADMIN
else:
	print(danger, '\nYou provided in invalid resource name.')
	print(reset)
	arg_parser.print_help()
	sys.exit()

# Check to see if any refresh token is given in the arguments
# If both are given, will use -r
# If no arguments are given, will look in the REFRESH_TOKEN environment variable
if args.refresh_token is None and args.refresh_token_file is None:
	try:
		REFRESH_TOKEN = os.environ['REFRESH_TOKEN']
	except KeyError as ke:
		print(danger, '\n\tNo refresh token found.\n', reset)
		arg_parser.print_help()
		sys.exit()
elif args.refresh_token is None:
	path = args.refresh_token_file
	try:
		with open(path, encoding='UTF-8') as json_file:
			json_file_data = json.load(json_file)
			json_file.close()
	except OSError as e:
		print(str(e))
		sys.exit()
	REFRESH_TOKEN = json_file_data['refresh_token']
else:
	REFRESH_TOKEN = args.refresh_token

# Setting up our post request
headers = {
	'User-Agent': USER_AGENT
}

data = {
	'client_id': CLIENT_ID,
	'grant_type': 'refresh_token',
	'scope': "openid",
	'resource': RESOURCE,
	'refresh_token': REFRESH_TOKEN
}

URI = 'https://login.microsoftonline.com/Common/oauth2/token'

# Sending the request
try:
	response = requests.post(URI, data=data, headers=headers)
	json_data = response.json()
	response.raise_for_status()
except requests.exceptions.HTTPError as he:
	print(danger)
	print(json_data['error'])
	print(json_data['error_description'])
	print(reset)
	sys.exit()

# Write the new token data to file
with open(outfile, 'w+', encoding='UTF-8') as f:
	f.write(json.dumps(json_data))
	f.close()

# Show the user the requested access and refresh tokens
print(success + 'Resource:\n' + reset + json_data['resource'] + '\n')
print(success + 'Access Token:\n' + reset + json_data['access_token'] + '\n')
print(success + 'Refresh Token:\n' + reset + json_data['refresh_token'] + '\n')

# Calculate the expired time
expires = json_data['expires_on']
print(success + 'Expires On:\n' + reset + time.ctime(int(expires)))
