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

import os
import sys
import time
import json
import argparse
import colorama
import requests

DESCRIPTION = '''
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
'''

# Set up our colors
colorama.init()
SUCCESS = colorama.Fore.GREEN
DANGER = colorama.Fore.RED
WARNING = colorama.Fore.YELLOW
RESET = colorama.Style.RESET_ALL
VALID = colorama.Fore.CYAN

# For use querying graph api for users and group membership
USERS_ENDPOINT_BASE = 'https://graph.microsoft.com/v1.0/users?$select='
GROUPS_ENDPOINT_BASE = 'https://graph.microsoft.com/v1.0/users/'
GROUPS_ENDPOINT_END = '/transitiveMemberOf'

USERS_SELECT_PARAMS_DICT = {
	'id': 'UID_Object_ID', # unique identifier / objectId
	'displayName': 'Display_Name', # Name displayed in address book
	'userType': 'User_Type', # Member | Guest
	'onPremisesSecurityIdentifier': 'Security_Identifier_(SID)_On-Prem'
}

USERS_SELECT_PARAMS = []
for param_key in USERS_SELECT_PARAMS_DICT:
	USERS_SELECT_PARAMS.append(param_key)

USERS_SELECT_PARAMS_STRING = str(USERS_SELECT_PARAMS)[1:][:-1].replace('\'','').replace(' ', '')

USER_ENDPOINT = USERS_ENDPOINT_BASE + USERS_SELECT_PARAMS_STRING

# For use when requesting new access tokens with refresh token
URI = 'https://login.microsoftonline.com/Common/oauth2/token'
CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

# User agent to use with requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0'

def main():
	"""Runner method"""
	arg_parser = argparse.ArgumentParser(
		prog='get_group_members.py',
		usage=SUCCESS + '%(prog)s' + RESET + \
			' [-t|--graph_token <graph_token>]' + \
			' [-r|--refresh_token <refresh_token>]',
		description=DESCRIPTION,
		formatter_class=argparse.RawDescriptionHelpFormatter)
	arg_parser.add_argument(
		'-t',
		'--graph_token',
		metavar='<graph_token>',
		dest='graph_token',
		type=str,
		help='The ms_graph token you would like to use',
		required=False)
	arg_parser.add_argument(
		'-r',
		'--refresh_token',
		metavar='<refresh_token>',
		dest='refresh_token',
		type=str,
		help='The refresh token you would like to use',
		required=False)
	arg_parser.add_argument('-R',
		'--refresh_token_file',
		metavar='<refresh_token_file>',
		dest='refresh_token_file',
		type=str,
		help='A JSON file saved from token_juggle.py ' \
			'containing the refresh token you would like to use.',
		required=False)
	arg_parser.add_argument('-o',
		'--outfile_path',
		metavar='<path>',
		dest='outfile_path',
		type=str,
		help='The path of where you want '\
			'the group membership data saved.'\
			'\nIf not supplied, module defaults to '\
			'the current directory.',
		required=False)

	args = arg_parser.parse_args()

	# Handle outfile path
	outfile_path_base = args.outfile_path
	if outfile_path_base is None:
		outfile_path_base = time.strftime('%Y-%m-%d_%H-%M-%S_')
	elif outfile_path_base[-1] != '/':
		outfile_path_base = outfile_path_base + '/' + time.strftime('%Y-%m-%d_%H-%M-%S_')
	outfile_raw_json = outfile_path_base + 'group_members_raw.json'
	outfile_condensed = outfile_path_base + 'group_members_condensed.json'
	outfile_bloodhound = outfile_path_base + 'group_members_bloodhound.json'

	# Check to see if any graph or refresh token is given in the arguments
	# If both are given, will use graph token
	# If no token given, will check for a refresh token file
	# If no arguments are given, will look in the REFRESH_TOKEN environment variable
	if args.refresh_token is None and args.graph_token is None and \
		args.refresh_token_file is None:
		try:
			refresh_token = os.environ['REFRESH_TOKEN']
		except KeyError:
			print(DANGER, '\n\tNo refresh token found.\n', RESET)
			arg_parser.print_help()
			sys.exit()
	elif args.refresh_token is None and args.graph_token is None:
		path = args.refresh_token_file
		try:
			with open(path, encoding='UTF-8') as json_file:
				json_file_data = json.load(json_file)
				json_file.close()
		except OSError as error:
			print(str(error))
			sys.exit()
		refresh_token = json_file_data['refresh_token']
	elif args.graph_token is not None:
		graph_token = args.graph_token
	else:
		refresh_token = args.refresh_token

	# If we have a refresh token, use it to request the necessary graph access token
	if refresh_token is not None:
		# Setting up our post request
		headers = {
			'User-Agent': USER_AGENT
		}
		# body of our request
		data = {
			'client_id': CLIENT_ID,
			'resource': 'https://graph.microsoft.com',
			'grant_type': 'refresh_token',
			'refresh_token': refresh_token,
			'scope': 'openid',
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
		graph_token = json_data['access_token']


	# Getting our first (only?) page of user results
	headers = {
		'Authorization': 'Bearer ' + graph_token
	}
	response = requests.get(USER_ENDPOINT, headers=headers).json()
	raw_user_json_data = {'value': []}
	try:
		response_users = response['value']
	except KeyError:
		print(response)
		print(f'{DANGER}Error retrieving users{RESET}')
		sys.exit()
	for user in response_users:
		raw_user_json_data['value'].append(user)
	try:
		next_link = response['@odata.nextLink']
	except KeyError:
		next_link = None

	# If next_link is not None, then the results are paged
	# We iterate through the paged results to build out our full user list
	while next_link is not None:
		response = requests.get(next_link, headers=headers).json()
		response_users = response['value']
		for user in response_users:
			raw_user_json_data['value'].append(user)
		try:
			next_link = response['@odata.nextLink']
		except KeyError:
			next_link = None

	# At this point we have a full user collection
	# We will use this collection to query group transitive membership
	raw_group_json_data = {'value': {}}
	for user in raw_user_json_data['value']:
		raw_group_json_data['value'][user['id']] = {
			'id': str(user['id']),
			'displayName': str(user['displayName']),
			'userType': str(user['userType']),
			'onPremisesSecurityIdentifier': str(user['onPremisesSecurityIdentifier']),
			'memberOf': []
		}
		group_membership_endpoint = GROUPS_ENDPOINT_BASE + user['id'] + GROUPS_ENDPOINT_END
		group_membership_resp = requests.get(group_membership_endpoint, headers=headers).json()
		for member_of_group in group_membership_resp['value']:
			raw_group_json_data['value'][user['id']]['memberOf'].append(member_of_group)
		try:
			next_link = group_membership_resp['@odata.nextLink']
		except KeyError:
			next_link = None
		# If next_link is not None, then the results are paged
		# We iterate through the paged results to build out our full memberOf list
		while next_link is not None:
			group_membership_resp = requests.get(next_link, headers=headers).json()
			for member_of_group in group_membership_resp['value']:
				raw_group_json_data['value'][user['id']]['memberOf'].append(member_of_group)
			try:
				next_link = group_membership_resp['@odata.nextLink']
			except KeyError:
				next_link = None

	count = 0

	# Processing raw data
	condensed_group_json_data = {}
	bloodhound_data = []
	for properties in raw_group_json_data['value'].values():
		print(f'{VALID}[+]{RESET} {properties["displayName"]}:')
		condensed_group_json_data[properties['id']] = {
			'id': properties['id'],
			'userType': properties['userType'],
			'onPremisesSecurityIdentifier': properties['onPremisesSecurityIdentifier'],
			'memberOf': {}
		}
		print()
		print(f'{SUCCESS}Object ID{RESET}: {properties["id"]}')
		print(f'{SUCCESS}User Type{RESET}: {properties["userType"]}')
		print(f'{SUCCESS}On-Prem SID{RESET}: {properties["onPremisesSecurityIdentifier"]}')
		print(f'{SUCCESS}Member Of{RESET}:')
		for group_member_of in properties['memberOf']:
			count = count + 1
			if properties['userType'] == 'Member':
				user_type = 'User'
			else:
				user_type = properties['userType']
			if properties['onPremisesSecurityIdentifier'] == 'None':
				user_security_identifier = ''
			else:
				user_security_identifier = properties['onPremisesSecurityIdentifier']
			try:
				security_identifier = group_member_of['onPremisesSecurityIdentifier']
			except KeyError:
				security_identifier = ''
			bloodhound_data.append({
				'GroupName': group_member_of['displayName'],
				'GroupID': group_member_of['id'],
				'GroupOnPremID': security_identifier,
				'MemberName': properties['displayName'],
				'MemberID': properties['id'],
				'MemberType': user_type,
				'MemberOnPremID': user_security_identifier
			})
			condensed_group_json_data[properties['id']]['memberOf'][group_member_of['id']] = {}
			print(f'\t{SUCCESS}Group{RESET}: {group_member_of["displayName"]}')
			for prop, val in group_member_of.items():
				if val is not None:
					condensed_group_json_data[properties['id']]['memberOf'][group_member_of['id']][prop] = val
				if val is not None and prop not in ['displayName','proxyAddresses','@odata.type']:
					print(f'\t\t{SUCCESS}{prop}{RESET}: {str(val)}')
		print()

	# Writing to raw_json_out
	print(f'{SUCCESS}[+]{RESET} Writing raw data to {outfile_raw_json}')
	with open(outfile_raw_json, 'w+', encoding='UTF-8') as raw_json_out:
		json.dump(raw_group_json_data, raw_json_out, indent=4)

	# Writing condensed_json_out
	print(f'{SUCCESS}[+]{RESET} Writing condensed data to {outfile_condensed}')
	with open(outfile_condensed, 'w+', encoding='UTF-8') as condensed_json_out:
		json.dump(condensed_group_json_data, condensed_json_out, indent=4)

	# Writing BloodHound compatible azgroupmembers.json
	print(f'{SUCCESS}[+]{RESET} Writing bloodhound data to {outfile_bloodhound}')
	bloodhound_json_data = {
		'meta': {
			'count': count,
			'type': 'azgroupmembers',
			'version': 4
		},
		'data': bloodhound_data
	}
	with open(outfile_bloodhound, 'w+', encoding='UTF-8') as bloodhound_out:
		json.dump(bloodhound_json_data, bloodhound_out, indent=4)


if __name__ == '__main__':
	main()
	sys.exit()
