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
'''

# Set up our colors
colorama.init()
SUCCESS = colorama.Fore.GREEN
DANGER = colorama.Fore.RED
WARNING = colorama.Fore.YELLOW
RESET = colorama.Style.RESET_ALL
VALID = colorama.Fore.CYAN

# For use querying graph api for users
ENDPOINT_BASE = 'https://graph.microsoft.com/v1.0/users?$select='
SELECT_PARAMS_DICT = {
	#'skills': 'User_Skills', List of user skills | Not currently supported
	#'responsibilities': 'User_Responsibilities', user responsibilities | Not currently supported
	#'schools': 'Schools_Attended', Schools the user attended | Not currently supported
	#'preferredName': 'User_Preferred_Name', preferred name for user | Not currently supported
	#'pastProjects': 'Past_User_Projects',List of past projects worked on | Not currently supported
	#'aboutMe': 'About_Me', User self description | Not currently supported
	#'birthday': 'Birthday', Birthday of user | Not currently supported
	#'hireDate': 'Hired_Date', date time of user hire Not currently supported (Sharepoint)
	#'interests': 'Interests', User described interests | Not currently supported
	#'mailboxSettings': 'Mailbox_Settings', Settings for primary mailbox of signed in user |
		# Not currently supported
	#'mySite': 'Personal_Site', User personal website | Not currently supported
	'id': 'UID_Object_ID', # unique identifier / objectId
	'accountEnabled': 'Account_Enabled', # true if enabled
	'displayName': 'Display_Name', # Name displayed in address book
	'givenName': 'First_Name', # User's first name
	'surname': 'Last_Name', # User's last name
	'userType': 'User_Type', # Member | Guest
	'lastPasswordChangeDateTime': 'Last_Changed_Password',
		# Datetime when password last changed or created
	'passwordPolicies': 'Password_Policies_Set',
		# DisabledStrongPassword | DisabledPasswordExpiration |
		# DisabledStrongPassword, DisabledPasswordExpiration
	'passwordProfile': 'Password_Profile',
		# Displays user's password when profile is created
	'companyName': 'Company_Name', # Company name associated with user
	'createdDateTime': 'Created_On', # Date user object created
	'creationType': 'Creation_Type', # school/work=null|external=Invitation|AAD B2C=LocalAccount|
		# self-service signup internal=EmailVerified|self-service signup external=SelfServiceSignUp
	'deletedDateTime': 'Date_User_Deleted', # date and time user was deleted
	'employeeId': 'Employee_ID', # Organization set employee identifier
	'employeeType': 'Enterprise_Worker_Type', # Employee|Contractor|Consultant|Vendor
	'employeeHireDate': 'Date_User_Hired', # date and time user was hired
	'jobTitle': 'Job_Title', # User job title
	'department': 'Department', # department where user works
	'officeLocation': 'Office_Location', # Office location at place of business
	'employeeOrgData': 'Employee_Organization_Data', # Includes the division worked in and
		# cost center associated with the user
	'mail': 'Email', # SMTP address for the user
	'mailNickname': 'Email_Alias', # Mail alias for user
	'proxyAddress': 'Proxy_Email_Addresses', # other valid email addresses that proxy to user
	'identities': 'Equivalent_Identities', # Multiple identites that may sign in as user
	'otherMails': 'Alternate_Email', # additional email addresses for user
	'imAddress': 'IM_VOIP_SIP_Address',
		# Instant message voice over IP session initiation protocol addresses
	'businessPhones': 'Business_Phone_Numbers', # Telephone numbers for user
	'mobilePhone': 'Mobile_Phone', # primary cellular phone number for user
	'faxNumber': 'Fax_Number', # User's fax number
	'country': 'Country', # Country User Located in
	'state': 'State', # State user lives in
	'city': 'City', # City User Located in
	'streetAddress': 'Street_Address', # street address where user lives
	'postalCode': 'Postal_Code', # User postal code
	'ageGroup': 'Age_Group', # null|Minor|NotAdult|Adult
	'consentProvidedForMinor': 'Consent_For_Minor_Provided', # null|Granted|Denied|NotRequired
	'legalAgeGroupClassification': 'Legal_Age_Group',
		# null|MinorWithOutParentalConsent|MinorWithParentalConsent|
		# MinorNoParentalConsentRequired|NotAdult|Adult
	'externalUserState': 'External_User_Invitation_Status', # PendingAcceptance|Accepted|null
	'externalUserStateChangeDateTime': 'Exteranl_User_Invitation_Status_Last_Changed',
		# datetime when externalUserState last changed
	'onPremisesDistinguishedName': 'Distinguished_Name_On-Prem', # On-Prem AD distinguished name
	'onPremisesDomainName': 'Domain_Name-On-Prem', # On-Prem dnsDomainName/domainFQDN
	'onPremisesExtensionAttributes': 'Custom_Exchange_Attributes_On-Prem', # ???
	'onPremisesImmutableId': 'Immutable_ID-On_Prem', # Associates On-Prem AD to AAD User
	'onPremisesLastSyncDateTime': 'Last_Time_Synced_With_On-Prem',
		# time at which synced with on-prem AD
	'onPremisesProvisioningErrors': 'Errors_Syncing_With_On-Prem',
		# Errors when using Microsoft synchonization product during provisioning
	'onPremisesSamAccountName': 'SAM_Account_Name_On-Prem',
		# On-Prem samAccountName synchronized from on-prem AD
	'onPremisesSecurityIdentifier': 'Security_Identifier_(SID)_On-Prem',
	'onPremisesSyncEnabled': 'On-Prem_Sync_Enabled',
		# synced=true | no longer synced=false | never synced=null
	'onPremisesUserPrincipalName': 'User_Principal_Name_On-Prem',
		# On-Prem AD userPrincipalName
	'preferredDataLocation': 'User_Preferred_Data_Location', # preferred data location for user
	'preferredLanguage': 'User_Preferred_Language', # preferred language for the user
	'provisionedPlans': 'User_Provisioned_Plans', # plans provisioned for the user
	'assignedLicenses': 'Assigned_Licenses', # Licenses assigned to user (or group)
	'licenseAssignmentStates': 'Current_License_States', # current state of license assignments
	'assignedPlans': 'Assigned_Plans', # Plans assigned to user
	'refreshTokensValidFromDateTime': 'Refresh_Token_Not_Valid_Before',
		# Any refresh tokens before this time are invalid
	'showInAddressList': 'Show_User_In_Outlook_Address_List', # true | false
	'signInSessionsValidFromDateTime': 'Sign-In_Session_Not_Valid_Before',
		# Any sessions before this time are invalid
	'usageLocation': 'User_Usage_Location', # country code to help with legal requirements
	'userPrincipalName': 'User_Principal_Name', # UPN - maps to email
	'isResourceAccount': 'Is_Resource_Account' # Not currently used, reserved for future use
}

SELECT_PARAMS = []
for param_key in SELECT_PARAMS_DICT:
	SELECT_PARAMS.append(param_key)

SELECT_PARAMS_STRING = str(SELECT_PARAMS)[1:][:-1].replace('\'','').replace(' ', '')

ENDPOINT = ENDPOINT_BASE + SELECT_PARAMS_STRING

# For use when requesting new access tokens with refresh token
URI = 'https://login.microsoftonline.com/Common/oauth2/token'
CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

# User agent to use with requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0'

def transpose_user(user):
	"""Takes in user result from Graph and morphs into something we want"""
	return_user = {}
	for prop, readable in SELECT_PARAMS_DICT.items():
		try:
			if isinstance(user[prop], list) and len(user[prop]) == 0:
				return_user[readable] = 'None'
			else:
				return_user[readable] = str(user[prop])
		except KeyError:
			pass

	return return_user

def main():
	"""Runner method"""
	arg_parser = argparse.ArgumentParser(
		prog='get_users.py',
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
			'the user data saved.'\
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
	outfile_raw_json = outfile_path_base + 'users_raw.json'
	outfile_condensed = outfile_path_base + 'users_condensed.json'
	outfile_bloodhound = outfile_path_base + 'users_bloodhound.json'

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

	response = requests.get(ENDPOINT, headers=headers).json()
	raw_json_data = {'value': []}
	users_result = {}
	try:
		response_users = response['value']
	except KeyError:
		print(f'{DANGER}Error retrieving users{RESET}')
		sys.exit()
	for user in response_users:
		raw_json_data['value'].append(user)
		users_result[user['id']] = transpose_user(user)

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
			raw_json_data['value'].append(user)
			users_result[user['id']] = transpose_user(user)
		try:
			next_link = response['@odata.nextLink']
		except KeyError:
			next_link = None

	# Go through our raw json response data and build out a more readable user collection
	condensed_json_data = {'users': {}}
	for object_id, values in users_result.items():
		condensed_json_data['users'][object_id] = {}
		for key, value in values.items():
			if key in ('Assigned_Plans', 'User_Provisioned_Plans',\
				'Current_License_States', 'Assigned_Licenses'):
				continue
			if key == 'Custom_Exchange_Attributes_On-Prem':
				include_exchange_attr = False
				json_values = json.loads(value.replace('\'', '\"').replace('None', 'null'))
				for exchange_value in json_values.values():
					if exchange_value is not None:
						include_exchange_attr = True
						break
				if include_exchange_attr:
					condensed_json_data['users'][object_id][key] = value
					print(f'{SUCCESS}{key}{RESET}:\t{value}'.expandtabs(56))
			elif value != 'None':
				condensed_json_data['users'][object_id][key] = value
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
	user_count = len(raw_json_data['value'])
	parts = graph_token.split('.')
	payload = parts[1]
	payload_string = base64.b64decode(payload + '==')
	payload_json = json.loads(payload_string)
	token_tenant_id  = payload_json['tid']
	bloodhound_json_data = {
		'meta': {
			'count': user_count,
			'type': 'azusers',
			'version': 4
		},
		'data': []
	}
	for user in raw_json_data['value']:
		if '#EXT#' not in user['userPrincipalName']:
			tenant_id = token_tenant_id
		else:
			tenant_id = None
		bloodhound_json_data['data'].append({
			'DisplayName': user['userPrincipalName'].split('@')[0],
			'UserPrincipalName': user['userPrincipalName'],
			'OnPremisesSecurityIdentifier': user['onPremisesSecurityIdentifier'],
			'ObjectID': user['id'],
			'TenantID': tenant_id
		})
	with open(outfile_bloodhound, 'w+', encoding='UTF-8') as bloodhound_json_out:
		json.dump(bloodhound_json_data, bloodhound_json_out, indent = 4)

if __name__ == '__main__':
	main()
	sys.exit()
