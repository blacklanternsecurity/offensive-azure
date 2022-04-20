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

DESCRIPTION = '''
	=====================================================================================
	# Requests a new access token for a Microsoft/Azure resource using a refresh token. #
	#                                                                                   #
	# This script will attempt to load a refresh token from a REFRESH_TOKEN             #
	# environment variable if none is passed with '-r' or '-R'.                         #
	=====================================================================================
'''

# Setup argparse stuff
RESOURCE_CHOICES = [
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

URI = 'https://login.microsoftonline.com/Common/oauth2/token'

# Set up our colors
colorama.init()
SUCCESS = colorama.Fore.GREEN
DANGER = colorama.Fore.RED
WARNING = colorama.Fore.YELLOW
RESET = colorama.Style.RESET_ALL

CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

def main():
	"""
	Main runner function

	Takes in a refresh token and target resource
	Returns a new access token + refresh token
	pair for target resource
	"""
	arg_parser = argparse.ArgumentParser(prog='token_juggle.py',
					usage=SUCCESS + '%(prog)s' + WARNING + ' <resource> ' + \
					RESET +'[-r \'refresh_token\' | -R \'./path/to/refresh_token.json\']',
					description=DESCRIPTION,
					formatter_class=argparse.RawDescriptionHelpFormatter)
	arg_parser.add_argument('Resource',
				metavar='resource',
				type=str,
				help='The target Microsoft/Azure resource.\nChoose from the following: ' + \
					str(RESOURCE_CHOICES).replace('\'', '').replace('[','').replace(']',''),
				choices=RESOURCE_CHOICES)
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

	# Initializing
	refresh_token = ''

	# Set our resource based on position argument
	if args.Resource == 'win_core_management':
		resource = WIN_CORE_MANAGEMENT
	elif args.Resource == 'azure_management':
		resource = AZURE_MANAGEMENT
	elif args.Resource == 'graph':
		resource = GRAPH
	elif args.Resource == 'ms_graph':
		resource = MS_GRAPH
	elif args.Resource == 'ms_manage':
		resource = MS_MANAGE
	elif args.Resource == 'teams':
		resource = TEAMS
	elif args.Resource == 'office_apps':
		resource = OFFICE_APPS
	elif args.Resource == 'office_manage':
		resource = OFFICE_MANAGE
	elif args.Resource == 'outlook':
		resource = OUTLOOK
	elif args.Resource == 'substrate':
		resource = SUBSTRATE
	elif args.Resource == 'm365_admin':
		resource = M365_ADMIN
	else:
		print(DANGER, '\nYou provided in invalid resource name.')
		print(RESET)
		arg_parser.print_help()
		sys.exit()

	# Check to see if any refresh token is given in the arguments
	# If both are given, will use -r
	# If no arguments are given, will look in the REFRESH_TOKEN environment variable
	if args.refresh_token is None and args.refresh_token_file is None:
		try:
			refresh_token = os.environ['REFRESH_TOKEN']
		except KeyError:
			print(DANGER, '\n\tNo refresh token found.\n', RESET)
			arg_parser.print_help()
			sys.exit()
	elif args.refresh_token is None:
		path = args.refresh_token_file
		try:
			with open(path, encoding='UTF-8') as json_file:
				json_file_data = json.load(json_file)
				json_file.close()
		except OSError as error:
			print(str(error))
			sys.exit()
		refresh_token = json_file_data['refresh_token']
	else:
		refresh_token = args.refresh_token

	# Setting up our post request
	headers = {
		'User-Agent': USER_AGENT
	}

	data = {
		'client_id': CLIENT_ID,
		'resource': resource,
		'grant_type': 'refresh_token',
		'refresh_token': refresh_token,
		'scope': 'openid',
		'optionalClaims': {
			'accessToken': [
				{'name': 'acct'}, # User account status (tenant member = 0; guest = 1)
				{'name': 'auth_time'}, # Time when the user last authenticated
				{'name': 'ctry'}, # Users country/region
				{'name': 'email'}, # Reported user email address
				{'name': 'fwd'}, # Original IPv4 Address of requesting client (when inside VNET)
				{'name': 'groups'}, # GroupMembership
				{'name': 'idtyp'}, # App for app-only token, or app+user
				{'name': 'login_hint'}, # Login hint
				{'name': 'sid'}, # Session ID
				{'name': 'tenant_ctry'}, # Tenant Country
				{'name': 'tenant_region_scope'}, # Tenant Region
				{'name': 'upn'}, # UserPrincipalName
				{'name': 'verified_primary_email'}, # User's PrimaryAuthoritativeEmail
				{'name': 'verified_secondary_email'}, # User's SecondaryAuthoritativeEmail
				{'name': 'vnet'}, # VNET specifier
				{'name': 'xms_pdl'}, # Preferred data location
				{'name': 'xms_pl'}, # User's preferred language
				{'name': 'xms_tpl'}, # Target Tenants preferred language
				{'name': 'ztdid'}, # Device Identity used for Windows AutoPilot
				{'name': 'ipaddr'}, # IP Address the client logged in from
				{'name': 'onprem_sid'}, # On-Prem Security Identifier
				{'name': 'pwd_exp'}, # Password Expiration Time (datetime)
				{'name': 'pwd_url'}, # Change password URL
				{'name': 'in_corp'}, # If client logs in within the corporate network (based off "trusted IPs")
				{'name': 'family_name'}, # Last Name
				{'name': 'given_name'}, # First Name
				{'name': 'upn'}, # User Principal Name
				{'name': 'aud'}, # Audience/Resource the token is for
				{'name': 'preferred_username'}, # Preferred username
			]
		}
	}

	# Sending the request
	json_data = {}
	try:
		response = requests.post(URI, data=data, headers=headers)
		json_data = response.json()
		response.raise_for_status()
	except requests.exceptions.HTTPError:
		print(DANGER)
		print(json_data['error'])
		print(json_data['error_description'])
		print(RESET)
		sys.exit()

	# Write the new token data to file
	with open(outfile, 'w+', encoding='UTF-8') as file:
		file.write(json.dumps(json_data))
		file.close()

	# Show the user the requested access and refresh tokens
	print(SUCCESS + 'Resource:\n' + RESET + json_data['resource'] + '\n')
	print(SUCCESS + 'Scope:\n' + RESET + json_data['scope'] + '\n')
	print(SUCCESS + 'Access Token:\n' + RESET + json_data['access_token'] + '\n')
	print(SUCCESS + 'Refresh Token:\n' + RESET + json_data['refresh_token'] + '\n')

	# Calculate the expired time
	expires = json_data['expires_on']
	print(SUCCESS + 'Expires On:\n' + RESET + time.ctime(int(expires)))

if __name__ == '__main__':
	main()
	sys.exit()
