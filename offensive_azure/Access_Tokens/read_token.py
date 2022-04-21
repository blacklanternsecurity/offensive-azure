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
import base64
import json
import datetime
import argparse
import colorama
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
import requests

DESCRIPTION = '''
	==========================================================
	#                                                        #
	#  Reads an access token for a Microsoft/Azure resource  #
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

KEY_ENDPOINT = 'https://login.microsoftonline.com/common/discovery/keys'

def main():
	"""Runner method"""
	arg_parser = argparse.ArgumentParser(
		prog='read_token.py',
		usage=SUCCESS + '%(prog)s' + RESET + \
			' [-t|--token <access_token>]',
		description=DESCRIPTION,
		formatter_class=argparse.RawDescriptionHelpFormatter)
	arg_parser.add_argument(
		'-t',
		'--token',
		metavar='<access_token>',
		dest='access_token',
		type=str,
		help='The token you would like to read',
		required=True)

	args = arg_parser.parse_args()

	parts = args.access_token.split('.')

	head = parts[0]
	payload = parts[1]
	signature = parts[2]

	# Parsing access token information
	payload_string = base64.b64decode(payload + '==')
	payload_json = json.loads(payload_string)
	try:
		iat_date = datetime.datetime.fromtimestamp(payload_json['iat'])
		payload_json['iat'] = iat_date.strftime('%Y-%m-%d, %H:%M:%S')
	except KeyError:
		payload_json['iat'] = ''
	try:
		nbf_date = datetime.datetime.fromtimestamp(payload_json['nbf'])
		payload_json['nbf'] = nbf_date.strftime('%Y-%m-%d, %H:%M:%S')
	except KeyError:
		payload_json['nbf'] = ''
	try:
		exp = payload_json['exp']
		exp_date = datetime.datetime.fromtimestamp(payload_json['exp'])
		payload_json['exp'] = exp_date.strftime('%Y-%m-%d, %H:%M:%S')
	except KeyError:
		payload_json['exp'] = ''

	# Finagling amr response to be more readable
	try:
		auth_methods = str(payload_json['amr'])
		auth_methods = auth_methods.replace('pwd', 'Password')
		auth_methods = auth_methods.replace('rsa', 'Certificate_Or_Authenticator_App')
		auth_methods = auth_methods.replace('otp', 'One-time_Passcode_(email_or_text_message)')
		auth_methods = auth_methods.replace('fed', 'Federated_(JWT_or_SAML)')
		auth_methods = auth_methods.replace('wia', 'Windows_Integrated_Authentication')
		auth_methods = auth_methods.replace('mfa', 'Multi-factor_Authentication')
		auth_methods = auth_methods.replace('ngcmfa', 'Multi-factor_Equivalent_(Advanced_Credential_Type')
		auth_methods = auth_methods.replace('wiaormfa', 'Windows_Or_Multi-factor')
	except KeyError:
		auth_methods = ''

	# Finagling acr response to be more readable
	try:
		auth_class = payload_json['acr']
		if auth_class == 0:
			auth_class = 'Authentication_Does_Not_Meet_ISO/IEC_29115_Requirements'
		elif auth_class == 1:
			auth_class = 'Authentication_Meets_ISO/IEC_29115_Requirements'
	except KeyError:
		auth_class = ''

	# Finagling appidacr/azpacr response to be more readable
	try:
		client_auth = payload_json['appidacr']
		if client_auth == 0:
			client_auth = 'Public_Client'
		elif client_auth == 1:
			client_auth = 'Client_ID_And_Client_Secret_Used'
		elif client_auth == 2:
			client_auth = 'Client_Certificate_Used'
	except KeyError:
		try:
			client_auth = payload_json['azpacr']
		except KeyError:
			if client_auth == 0:
				client_auth = 'Public_Client'
			elif client_auth == 1:
				client_auth = 'Client_ID_And_Client_Secret_Used'
			elif client_auth == 2:
				client_auth = 'Client_Certificate_Used'

	# Finagling acct response to be more readable
	try:
		user_acct = payload_json['acct']
		if user_acct == 0:
			user_acct = 'Tenant_Member'
		elif user_acct == 1:
			user_acct = 'Tenant_Guest'
	except KeyError:
		user_acct = ''

	result = {
		'Initialized_At': payload_json['iat'],
		'Not_Valid_Before': payload_json['nbf'],
		'Expires': payload_json['exp'],
	}

	try:
		result['Resource'] = payload_json['aud']
	except KeyError:
		result['Resource'] = ''
	try:
		result['Identity_Provider_Issuer'] = payload_json['iss']
	except KeyError:
		result['Identity_Provider_Issuer'] = ''
	try:
		result['Token_Reuse_Claim'] = payload_json['aio']
	except KeyError:
		result['Token_Reuse_Claim'] = ''
	result['Authentication_Context_Class'] = auth_class
	result['Authentication_Methods'] = auth_methods
	try:
		result['Application_ID'] = payload_json['appid']
	except KeyError:
		try:
			result['Application_ID'] = payload_json['azp']
		except KeyError:
			result['Application_ID'] = ''
	result['Client_Authentication_Method'] = client_auth
	try:
		result['Last_Name'] = payload_json['family_name']
	except KeyError:
		result['Last_Name'] = ''
	try:
		result['First_Name'] = payload_json['given_name']
	except KeyError:
		result['First_Name'] = ''
	try:
		result['IP_Address'] = payload_json['ipaddr']
	except KeyError:
		result['IP_Address'] = ''
	try:
		result['Full_Name'] = payload_json['name']
	except KeyError:
		result['Full_Name'] = ''
	try:
		result['Verified_Service_Principal'] = payload_json['oid']
	except KeyError:
		result['Verified_Service_Principal'] = ''
	try:
		result['PUID'] = payload_json['puid']
	except KeyError:
		result['PUID'] = ''
	try:
		result['Internal_Revalidation_String'] = payload_json['rh']
	except KeyError:
		result['Internal_Revalidation_String'] = ''
	try:
		result['Consented Scopes'] = payload_json['scp']
	except KeyError:
		result['Consented Scopes'] = ''
	try:
		result['Subject_Authorization_Check_Value'] = payload_json['sub']
	except KeyError:
		result['Subject_Authorization_Check_Value'] = ''
	try:
		result['Tenant_Region_Scope'] = payload_json['tenant_region_scope']
	except KeyError:
		result['Tenant_Region_Scope'] = ''
	try:
		result['Tenant_ID'] = payload_json['tid']
	except KeyError:
		result['Tenant_ID'] = ''
	try:
		result['Human_Readable_Token_Subject'] = payload_json['unique_name']
	except KeyError:
		result['Human_Readable_Token_Subject'] = ''
	try:
		result['User_Principal_Name'] = payload_json['upn']
	except KeyError:
		result['User_Principal_Name'] = ''
	try:
		result['Unique_Token_Identifier'] = payload_json['uti']
	except KeyError:
		result['Unique_Token_Identifier'] = ''
	try:
		result['Token_Version'] = payload_json['ver']
	except KeyError:
		result['Token_Version'] = ''
	result['User_Account_Status'] = user_acct
	try:
		result['Last_Authenticated'] = payload_json['auth_time']
	except KeyError:
		result['Last_Authenticated'] = ''
	try:
		result['Users_Country'] = payload_json['ctry']
	except KeyError:
		result['Users_Country'] = ''
	try:
		result['Reported_User_Email'] = payload_json['email']
	except KeyError:
		result['Reported_User_Email'] = ''
	try:
		result['Originating_VNET_IPv4_Address'] = payload_json['fwd']
	except KeyError:
		result['Originating_VNET_IPv4_Address'] = ''
	try:
		result['Group_Membership'] = payload_json['groups']
	except KeyError:
		result['Group_Membership'] = ''
	try:
		result['Token_Type'] = payload_json['idtyp']
	except KeyError:
		result['Token_Type'] = ''
	try:
		result['Login_Hint'] = payload_json['login_hint']
	except KeyError:
		result['Login_Hint'] = ''
	try:
		result['Session_ID'] = payload_json['sid']
	except KeyError:
		result['Session_ID'] = ''
	try:
		result['Tenant_Country'] = payload_json['tenant_ctry']
	except KeyError:
		result['Tenant_Country'] = ''
	try:
		result['Verified_Primary_Email'] = payload_json['verified_primary_email']
	except KeyError:
		result['Verified_Primary_Email'] = ''
	try:
		result['Verified_Secondary_Email'] = payload_json['verified_secondary_email']
	except KeyError:
		result['Verified_Secondary_Email'] = ''
	try:
		result['VNET'] = payload_json['vnet']
	except KeyError:
		result['VNET'] = ''
	try:
		result['Preferred_Data_Location'] = payload_json['xms_pdl']
	except KeyError:
		result['Preferred_Data_Location'] = ''
	try:
		result['Preferred_Language'] = payload_json['xms_pl']
	except KeyError:
		result['Preferred_Language'] = ''
	try:
		result['Tenant_Preferred_Language'] = payload_json['xms_tpl']
	except KeyError:
		result['Tenant_Preferred_Language'] = ''
	try:
		result['Zero_Touch_Deployment_ID'] = payload_json['ztdid']
	except KeyError:
		result['Zero_Touch_Deployment_ID'] = ''
	try:
		result['On-Premises_Security_Identifier'] = payload_json['onprem_sid']
	except KeyError:
		result['On-Premises_Security_Identifier'] = ''
	try:
		result['Password_Expiration_Time'] = payload_json['pwd_exp']
	except KeyError:
		result['Password_Expiration_Time'] = ''
	try:
		result['Change_Password_URL'] = payload_json['pwd_url']
	except KeyError:
		result['Change_Password_URL'] = ''
	try:
		result['User_Within_Corporate_Network'] = payload_json['in_corp']
	except KeyError:
		result['User_Within_Corporate_Network'] = ''
	try:
		result['User_Roles_Allowed'] = payload_json['roles']
	except KeyError:
		result['User_Roles_Allowed'] = ''
	try:
		result['Tenant_Wide_User_Roles'] = payload_json['wids']
	except KeyError:
		result['Tenant_Wide_User_Roles'] = ''
	try:
		result['User_In_A_Group'] = payload_json['hasgroups']
	except KeyError:
		result['User_In_A_Group'] = ''
	try:
		result['Groups_List_URL'] = payload_json['groups:src1']
	except KeyError:
		result['Groups_List_URL'] = ''
	try:
		result['Additional_User_Name'] = payload_json['nickname']
	except KeyError:
		result['Additional_User_Name'] = ''

	# Check if token is expired
	current_time = datetime.datetime.now().timestamp()
	result['Expired'] = current_time > exp

	# Token signature verfication

	head_string = base64.b64decode(head + '==')
	head_json = json.loads(head_string)
	key_id = head_json['kid']

	if head_json['alg'] == 'RS256':
		response = requests.get(KEY_ENDPOINT).json()
		public_cert = None
		for key in response['keys']:
			if key['kid'] == key_id:
				public_cert = key['x5c']
				break
		if public_cert is not None:
			public_cert_bin = base64.b64decode(public_cert[0])
			jwt_data = f'{head}.{payload}'
			jwt_data_bin = base64.b64decode(jwt_data + '==')
			signature = signature.replace('-','+').replace('_','/') + '=='
			signature_bin = base64.b64decode(signature)
			for index in range(0, len(public_cert_bin), 1):
				try:
					byte = public_cert_bin[index]
					next_byte = public_cert_bin[index+1]
				except IndexError:
					result['Valid_Signature'] = 'Error'
					break
				if byte == 0x02 and next_byte & 0x80:
					index = index + 1
					if next_byte & 0x02:
						byte_one = str(public_cert_bin[index+2])
						while len(byte_one) % 8:
							byte_one = '0' + byte_one
						byte_two = str(public_cert_bin[index+1])
						while len(byte_two) % 8:
							byte_two = '0' + byte_two
						bytes_concat = byte_one + byte_two
						byte_count = int(bytes_concat, 2)
						index = index + 3
					elif next_byte & 0x01:
						byte_one = str(public_cert_bin[index+1])
						while len(byte_one) % 8:
							byte_one = '0' + byte_one
						byte_count = int(byte_one, 2)
						index = index + 2

					if public_cert_bin[index] == 0x00:
						index = index + 1
						byte_count = byte_count - 1

					modulus = public_cert_bin[index:index+byte_count]

					index = index + byte_count
					if public_cert_bin[index] == 0x02:
						index = index + 1
						byte_count = public_cert_bin[index]
						exponent = public_cert_bin[index:index+byte_count-1]
					else:
						result['Valid_Signature'] = 'Error'
						break
			if exponent and modulus:
				exponent_bin = ''
				for exp_byte in exponent:
					exp_bin = str(bin(exp_byte)).replace('0b', '')
					while len(exp_bin) % 8:
						exp_bin = '0' + exp_bin
					exponent_bin = exponent_bin + exp_bin
				modulus_bin = ''
				for mod_byte in modulus:
					mod_bin = str(bin(mod_byte)).replace('0b', '')
					while len(mod_bin) % 8:
						mod_bin = '0' + mod_bin
					modulus_bin = modulus_bin + mod_bin
				rsa = RSA.construct((int(modulus_bin, 2), int(exponent_bin, 2)))
				hash_msg = SHA.new()
				hash_msg.update(jwt_data_bin)
				verifier = PKCS1_PSS.new(rsa.publickey())
				valid = verifier.verify(hash_msg, signature_bin) # pylint: disable=not-callable
				result['Valid_Signature'] = valid
	else:
		result['Valid_Signature'] = 'Unsupported Algorithm'

	print()
	print(f'{WARNING}TOKEN INFORMATION{RESET}:')
	for key, value in result.items():
		if key == 'Expired' and value is True:
			print(f'{SUCCESS}{key}{RESET}: {DANGER}{value}{RESET}')
		elif key == 'Expired' and value is False:
			print(f'{SUCCESS}{key}{RESET}: {VALID}{value}{RESET}')
		elif key == 'Valid_Signature' and value is True:
			print(f'{SUCCESS}{key}{RESET}: {VALID}{value}{RESET}')
		elif key == 'Valid_Signature' and value is False:
			print(f'{SUCCESS}{key}{RESET}: {WARNING}Unable To Validate{RESET}')
		elif value != '':
			print(f'{SUCCESS}{key}{RESET}: {value}')
		else:
			continue


if __name__ == '__main__':
	main()
	sys.exit()
