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
import base64
import json
import argparse
import colorama
import requests

DESCRIPTION = '''
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
'''

# Set up our colors
colorama.init()
SUCCESS = colorama.Fore.GREEN
DANGER = colorama.Fore.RED
WARNING = colorama.Fore.YELLOW
RESET = colorama.Style.RESET_ALL
VALID = colorama.Fore.CYAN

# For use querying graph api for users
ENDPOINT_BASE = 'https://graph.microsoft.com/v1.0/groups?$select='

# For use when requesting new access tokens with refresh token
URI = 'https://login.microsoftonline.com/Common/oauth2/token'
CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

# User agent to use with requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0'

SELECT_PARAMS_DICT = {
	'allowExternalSender': 'External_Users_Can_Talk_To_Group',
	'assignedLabels': 'M365_Sensitivity_Label_Pairs',
	'assignedLicenses': 'Licenses_Assigned_To_Group',
	#'autoSubscribeNewMembers': 'New_Members_Subscribed_Automatically', Not Implemented
	'classification': 'Assigned_Classification',
	'createdDateTime': 'Time_Group_Created',
	'deletedDateTime': 'Time_Group_Deleted',
	'description': 'Group_Description',
	'displayName': 'Group_Display_Name',
	'expirationDateTime': 'Time_Group_Expires',
	'groupTypes': 'Group_Type',
		# Unified = M365 Group, DynamicMembership = Group has dynamic membership
		# Otherwise group is a security or distribution group
	#'hasMembersWithLicenseErrors': 'Members_Have_Licensing_Errors', Filter Only
	#'hideFromAddressLists': 'Hidden_From_Outlook_UI', Not Implemented
	#'hideFromOutlookClients': 'Hidden_From_Outlook_Clients', Not Implemented
	'id': 'Object_ID',
	#'isArchived': 'Is_Group_Team_Read-Only', Not Implemented
	'isAssignableToRole': 'Can_Group_Be_Assigned_To_Role',
	#'isSubscribedByMail': 'Is_Authenticated_User_Email_Subscribed_To_Group', Not Implemented
	'licenseProcessingState': 'Group_Member_License_Assignment_Status',
	'mail': 'Group_Email_Address',
	'mailEnabled': 'Group_Email_Enabled',
	'mailNickname': 'Group_Email_Alias',
	'membershipRule': 'Dynamic_Group_Membership_Rule',
	'membershipRuleProcessingState': 'Dynamic_Membership',
	'onPremisesLastSyncDateTime': 'Last_Time_Synced_On-Prem',
	'onPremisesProvisioningErrors': 'On-Prem_Synchronization_Errors',
	'onPremisesSamAccountName': 'On-Prem_SAM_Account_Name',
	'onPremisesSecurityIdentifier': 'On-Prem_Security_Identifier',
	'onPremisesSyncEnabled': 'Is_Group_Synced_On-Prem',
	'preferredDataLocation': 'M365_Preferred_Data_Location',
	'preferredLanguage': 'M365_Preferred_Language',
	'proxyAddress': 'Group_Proxy_Email_Addresses',
	'renewedDateTime': 'Group_Last_Renewed',
	'resourceBehaviorOptions': 'M365_Group_Behaviors',
		# AllowOnlyMembersToPost | HideGroupInOutlook | SubscribeNewGroupMembers
			# | WelcomeEmailDisabled
	'resourceProvisioningOptions': 'M365_Provisioned_Group_Resources',
	'securityEnabled': 'Security_Group',
	'securityIdentifier': 'Windows_Group_Security_Identifier',
	'theme': 'M365_Group_Color_Theme',
	#'unseenCount': 'Unread_Conversations_Count', Not Implemented
		# Count of conversations that have received new posts since authenticated users last visit
	'visibility': 'Group_Join_Policy/Group_Content_Visibility'
		# Private | Public | Hiddenmembership
}

SELECT_PARAMS = []
for param_key in SELECT_PARAMS_DICT:
	SELECT_PARAMS.append(param_key)

SELECT_PARAMS_STRING = str(SELECT_PARAMS)[1:][:-1].replace('\'','').replace(' ', '')

ENDPOINT = ENDPOINT_BASE + SELECT_PARAMS_STRING

def transpose_group(group):
	"""Takes in group result from Graph and morphs into something we want"""
	return_group = {}
	for prop, readable in SELECT_PARAMS_DICT.items():
		try:
			if isinstance(group[prop], list) and len(group[prop]) == 0:
				return_group[readable] = 'None'
			else:
				return_group[readable] = str(group[prop])
		except KeyError:
			pass

	return return_group

def main():
	"""Runner method"""
	arg_parser = argparse.ArgumentParser(
		prog='get_groups.py',
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
			'the group data saved.'\
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
	outfile_raw_json = outfile_path_base + 'groups_raw.json'
	outfile_condensed = outfile_path_base + 'groups_condensed.json'
	outfile_bloodhound = outfile_path_base + 'groups_bloodhound.json'

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

	# Getting our first (only?) page of group results
	headers = {
		'Authorization': 'Bearer ' + graph_token
	}

	response = requests.get(ENDPOINT, headers=headers).json()
	raw_json_data = {'value': []}
	groups_result = {}
	try:
		response_groups = response['value']
	except KeyError:
		print(f'{DANGER}Error retrieving users{RESET}')
		sys.exit()
	for group in response_groups:
		raw_json_data['value'].append(group)
		groups_result[group['id']] = transpose_group(group)

	try:
		next_link = response['@odata.nextLink']
	except KeyError:
		next_link = None

	# If next_link is not None, then the results are paged
	# We iterate through the paged results to build out our full group list
	while next_link is not None:
		response = requests.get(next_link, headers=headers).json()
		response_groups = response['value']
		for group in response_groups:
			raw_json_data['value'].append(group)
			groups_result[group['id']] = transpose_group(group)
		try:
			next_link = response['@odata.nextLink']
		except KeyError:
			next_link = None

	# Go through our raw json response data and build out a more readable group collection
	condensed_json_data = {'groups': {}}
	for object_id, values in groups_result.items():
		condensed_json_data['groups'][object_id] = {}
		for key, value in values.items():
			if value != 'None':
				condensed_json_data['groups'][object_id][key] = value
				print(f'{SUCCESS}{key}{RESET}:\t{value}'.expandtabs(56))
		print()

	# Save raw json to file
	print(f'{SUCCESS}[+]{RESET} Writing raw response data to {WARNING}{outfile_raw_json}{RESET}')
	with open(outfile_raw_json, 'w+', encoding='UTF-8') as raw_json_out:
		json.dump(raw_json_data, raw_json_out, indent = 4)

	# save condensed output to file
	print(f'{SUCCESS}[+]{RESET} Writing condensed response ' + \
		f'data to {WARNING}{outfile_condensed}{RESET}')
	with open(outfile_condensed, 'w+', encoding='UTF-8') as condensed_json_out:
		json.dump(condensed_json_data, condensed_json_out, indent = 4)

	# save bloodhound-users.json
	print(f'{SUCCESS}[+]{RESET} Writing bloodhound data to {WARNING}{outfile_bloodhound}{RESET}')
	group_count = len(raw_json_data['value'])
	parts = graph_token.split('.')
	payload = parts[1]
	payload_string = base64.b64decode(payload + '==')
	payload_json = json.loads(payload_string)
	token_tenant_id  = payload_json['tid']
	bloodhound_json_data = {
		'meta': {
			'count': group_count,
			'type': 'azgroups',
			'version': 4
		},
		'data': []
	}
	for group in raw_json_data['value']:
		bloodhound_json_data['data'].append({
			'DisplayName': group['displayName'],
			'OnPremisesSecurityIdentifier': group['onPremisesSecurityIdentifier'],
			'ObjectID': group['id'],
			'TenantID': token_tenant_id
		})
	with open(outfile_bloodhound, 'w+', encoding='UTF-8') as bloodhound_json_out:
		json.dump(bloodhound_json_data, bloodhound_json_out, indent = 4)

if __name__ == '__main__':
	main()
	sys.exit()
