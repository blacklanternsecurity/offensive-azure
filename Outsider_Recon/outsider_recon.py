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
import time
import json
import dns.resolver
import dns.rcode
import xml.etree.ElementTree as ET
import argparse
import colorama
import requests

class OutsiderRecon:
	'''
	Contains all functions necessary to enumerate an Azure tenant
	given a domain that belongs to an Azure tenant.

	Methods
	-------
	enumerate_domain_info(domains, login_infos):
		Enumerates information about a domain, including DMARC, CloudSPF, CloudMX, DNS, STS, SSO

	enumerate_tenant_id(openid_config):
		Given an openid_config, will return the tenant ID

	enumerate_login_info(domain, username):
		Given a domain and optional username, will return the authentication related endpoints
		and information as they pertain to the supplied domain

	enumerate_openid(domain):
		Given a domain, will return the openid configuration information

	enumerate_tenant_domains(domain, user_agent='AutodiscoverClient'):
		Given a domain and optional user_agent, will return all domains
		registered to the same Azure tenant as the domain provided
	'''

	@staticmethod
	def enumerate_domain_info(self, domains, login_infos):
		domain_info = {}
		for domain in domains:
			domain_info[domain] = {}

			# Check if domain has SSO emabled
			domain_info[domain]['sso'] = False
			try:
				if login_infos[domain]['Desktop SSO Enabled'] == 'True':
					domain_info[domain]['sso'] = True
			except KeyError as key_error:
				pass

			# Check for Namespace
			try:
				domain_info[domain]['type'] = login_infos[domain]['Namespace Type']
			except KeyError as key_error:
				domain_info[domain]['type'] = 'Unknown'

			# Check for STS
			try:
				domain_info[domain]['sts'] = login_infos[domain]['Authentication URL']
			except KeyError as key_error:
				domain_info[domain]['sts'] = ''

			# Check if DNS Name resolves
			try:
				dns_response = dns.resolver.resolve(domain)
				if dns.rcode.to_text(dns_response.response.rcode()) == 'NOERROR':
					domain_info[domain]['dns'] = True
				else:
					domain_info[domain]['dns'] = False
					domain_info[domain]['cloudmx'] = False
					domain_info[domain]['cloudspf'] = False
					domain_info[domain]['dmarc'] = False
					continue
			except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as no_answer:
				domain_info[domain]['dns'] = False
				domain_info[domain]['cloudmx'] = False
				domain_info[domain]['cloudspf'] = False
				domain_info[domain]['dmarc'] = False
				continue

			# Check for CloudMX
			try:
				domain_info[domain]['cloudmx'] = False
				dns_response = dns.resolver.resolve(domain, 'MX')
				for answer in dns_response:
					if 'mail.protection.outlook.com' in str(answer):
						domain_info[domain]['cloudmx'] = True
						break
			except dns.exception.DNSException as dns_exception:
				pass
			# Check for CloudSPF
			try:
				domain_info[domain]['cloudspf'] = False
				dns_response = dns.resolver.resolve(domain, 'TXT')
				for answer in dns_response:
					if 'include:spf.protection.outlook.com' in str(answer):
						domain_info[domain]['cloudspf'] = True
						break
			except dns.exception.DNSException as dns_exception:
				pass
			# Check for DMARC
			try:
				domain_info[domain]['dmarc'] = False
				dns_response = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
				for answer in dns_response:
					if 'v=DMARC1' in str(answer):
						domain_info[domain]['dmarc'] = True
						break
			except dns.exception.DNSException as dns_exception:
				pass

		return domain_info

	@staticmethod
	def enumerate_tenant_id(self, openid_config):

		return openid_config['authorization_endpoint'].split('/')[3]

	@staticmethod
	def enumerate_login_info(self, domain, username):

		results = {}

		user = username + '@' + domain

		endpoint1 = 'https://login.microsoftonline.com/common/userrealm/%s?api-version=1.0' % (user)
		endpoint2 = 'https://login.microsoftonline.com/common/userrealm/%s?api-version=2.0' % (user)
		endpoint3 = 'https://login.microsoftonline.com/GetUserRealm.srf?login=%s' % (user)
		endpoint4 = 'https://login.microsoftonline.com/common/GetCredentialType'

		body = {
			'username': user,
			'isOtherIdpSupported': 'true',
			'checkPhones': 'true',
			'isRemoteNGCSupported': 'false',
			'isCookieBannerShown': 'false',
			'isFidoSupported': "false",
			'originalRequest': ''
		}

		json_data = json.dumps(body)

		headers4 = {
			'Content-Type': 'application/json; charset=utf-8',
		}

		user_realm_json1 = requests.get(endpoint1).json()
		user_realm_json2 = requests.get(endpoint2).json()
		user_realm_json3 = requests.get(endpoint3).json()
		user_realm_json4 = requests.post(endpoint4, headers=headers4, data=json_data).json()


		try:
			results['Account Type'] = user_realm_json1['account_type']
		except KeyError as key_error:
			pass
		try:
			results['Namespace Type'] = user_realm_json2['NameSpaceType']
		except KeyError as key_error:
			pass
		try:
			results['Domain Name'] = user_realm_json3['DomainName']
		except KeyError as key_error:
			pass
		try:
			results['Cloud Instance'] = user_realm_json1['cloud_instance_name']
		except KeyError as key_error:
			pass
		try:
			results['Cloud Instance Audience URN'] = user_realm_json1['cloud_audience_urn']
		except KeyError as key_error:
			pass
		try:
			results['Federation Brand Name'] = user_realm_json3['FederationBrandName']
		except KeyError as key_error:
			pass
		try:
			results['State'] = user_realm_json3['State']
		except KeyError as key_error:
			pass
		try:
			results['User State'] = user_realm_json3['UserState']
		except KeyError as key_error:
			pass
		try:
			results['Exists'] = user_realm_json4['IfExistsResult']
		except KeyError as key_error:
			pass
		try:
			results['Throttle Status'] = user_realm_json4['ThrottleStatus']
		except KeyError as key_error:
			pass
		try:
			results['Pref Credential'] = user_realm_json4['Credentials']['PrefCredential']
		except KeyError as key_error:
			pass
		try:
			results['Has Password'] = user_realm_json4['Credentials']['HasPassword']
		except KeyError as key_error:
			pass
		try:
			results['Domain Type'] = user_realm_json4['EstsProperties']['DomainType']
		except KeyError as key_error:
			pass
		try:
			results['Federation Protocol'] = user_realm_json1['federation_protocol']
		except KeyError as key_error:
			pass
		try:
			results['Federation Metadata URL'] = user_realm_json1['federation_metadata_url']
		except KeyError as key_error:
			pass
		try:
			results['Federation Active Authentication URL'] = user_realm_json1['federation_active_auth_url']
		except KeyError as key_error:
			pass
		try:
			results['Authentication URL'] = user_realm_json2['AuthUrl']
		except KeyError as key_error:
			pass
		try:
			results['Consumer Domain'] = user_realm_json2['ConsumerDomain']
		except KeyError as key_error:
			pass
		try:
			results['Federation Global Version'] = user_realm_json3['FederationGlobalVersion']
		except KeyError as key_error:
			pass
		try:
			results['Desktop SSO Enabled'] = user_realm_json4['EstsProperties']['DesktopSsoEnabled']
		except KeyError as key_error:
			pass

		return results

	@staticmethod
	def enumerate_openid(self, domain):

		endpoint = 'https://login.microsoftonline.com/%s/.well-known/openid-configuration' % (domain)

		openid_config_json = requests.get(endpoint).json()

		return openid_config_json

	@staticmethod
	def enumerate_tenant_domains(self, domain, user_agent='AutodiscoverClient'):
		headers = {
			'Content-Type': 'text/xml; charset=utf-8',
			'SOAPAction': '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
			'User-Agent': user_agent
		}

		xml = '''<?xml version="1.0" encoding="utf-8"?>
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
						<Domain>%s</Domain>
					</Request>
				</GetFederationInformationRequestMessage>
			</soap:Body>
		</soap:Envelope>''' % (domain)

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
			except ET.ParseError as e:
				continue

		domains = []

		for i in xml_response[1][0][0][3]:
			domains.append(i.text)

		return domains

	@staticmethod
	def main(self):
		# Set up our colors
		colorama.init()
		SUCCESS = colorama.Fore.GREEN
		DANGER = colorama.Fore.RED
		WARNING = colorama.Fore.YELLOW
		RESET = colorama.Style.RESET_ALL

		description = '''
  =====================================================================================
  # This module will enumerate all available information for a given target domain    #
  # within an Azure tenant. This does not require any level of pre-existing access.   #
  =====================================================================================
'''

		arg_parser = argparse.ArgumentParser(
			prog='outsider_recon.py',
			usage=SUCCESS + '%(prog)s' + WARNING + ' <domain>' + RESET + \
				' [-o|--outfile <path-to-file>] [-u|--user <user>]',
			description=description,
			formatter_class=argparse.RawDescriptionHelpFormatter)
		arg_parser.add_argument(
			'Domain',
			metavar='domain',
			type=str,
			help='The target Microsoft/Azure domain')
		arg_parser.add_argument(
			'-o',
			'--outfile-path',
			metavar='<path>',
			dest='outfile_path',
			type=str,
			help='(string) The path where you want the recon data (json object) saved.\n' \
				'If not supplied, module defaults to the current directory',
			required=False)
		arg_parser.add_argument(
			'-u',
			'--user',
			metavar='<username>',
			dest='user',
			type=str,
			help='(string) The user you want to use during enumeration. Do not include the' \
				' domain.\nIf not supplied, module defaults to "none"',
			required=False)

		args = arg_parser.parse_args()

		outfile_prefix = time.strftime('%Y-%m-%d_%H-%M-%S_' + args.Domain + '_')

		# Set a default path if none is given
		path = args.outfile_path
		if path is None:
			path = './'
		elif path[-1] != '/':
			path = path + '/'

		# Set a default user if none is given
		user = args.user
		if user is None:
			user = 'none'

		# Enumerating all domains for the tenant the passed in domain belongs to
		print(WARNING + 'Enumerating Other Domains Within Tenant' + RESET + '\n')
		domains_found = self.enumerate_tenant_domains(args.Domain)
		if domains_found is None:
			print(DANGER + 'It doesn\'t look like this is a domain in Azure. Check your domain or try something else.')
			sys.exit()
		for domain_found in domains_found:
			print(SUCCESS + '[+] ' + RESET + domain_found)
		print()

		# Enumerating the openid configuration for the tenant
		print(WARNING + 'Enumerating OpenID Configuration for Tenant' + RESET + '\n')
		openid_config = self.enumerate_openid(args.Domain)
		for elem in openid_config:
			print((SUCCESS + elem + RESET + ':\t' + str(openid_config[elem])).expandtabs(50))
		print()

		# Enumerating the login information for each domain discovered
		login_infos = {}
		print(WARNING + 'Enumerating User Login Information' + RESET + '\n')
		for domain_found in domains_found:
			user_realm_json = self.enumerate_login_info(args.Domain, user)
			login_infos[domain_found] = user_realm_json
			print(WARNING + '[+] ' + domain_found + ":" + RESET)
			print(WARNING + '========================' + RESET)
			for elem in user_realm_json:
				print((SUCCESS + elem + RESET + ":\t" + str(user_realm_json[elem])).expandtabs(50))
			print(WARNING + '========================' + RESET + '\n')
		print()

		# Enumerate the tenant ID
		print(WARNING + 'Tenant ID' + RESET + '\n')
		tenant_id = self.enumerate_tenant_id(openid_config)
		print(SUCCESS + '[+] ' + RESET + tenant_id)
		print()

		# Enumerate Domain Information (DNS, CLOUDMX, CLOUDSPF, DMARC, Identity Management, STS, SSO)
		print(WARNING + 'Enumerating Domain Information' + RESET + '\n')
		domain_info = self.enumerate_domain_info(domains_found, login_infos)
		for domain_name in domain_info:
			print(WARNING + '[+] ' + domain_name + ":" + RESET)
			print(WARNING + '========================' + RESET)
			for key, value in domain_info[domain_name].items():
				print((SUCCESS + key + RESET + ":\t" + str(value)).expandtabs(24))
			print(WARNING + '========================' + RESET + '\n')

		# Save our results to files

		## Save Domain List
		with open(path + outfile_prefix + 'domain_list.txt', 'w+', encoding='UTF-8') as file:
			for dom in domains_found:
				file.write(dom + '\n')
			file.close()

		## Save Tenant OpenID Configuration
		with open(path + outfile_prefix + 'tenant_openid_config.json', 'w+', encoding='UTF-8') as file:
			file.write(json.dumps(openid_config))
			file.close()

		## Save Domain Login Information
		with open(path + outfile_prefix + 'domain_login_information.json', 'w+', encoding='UTF-8') as file:
			file.write(json.dumps(login_infos))
			file.close()

		## Save Tenant ID
		with open(path + outfile_prefix + 'tenant_id.txt', 'w+', encoding='UTF-8') as file:
			file.write(tenant_id)
			file.close()

		## Save Domain Information
		with open(path + outfile_prefix + 'domain_information.json', 'w+', encoding='UTF-8') as file:
			file.write(json.dumps(domain_info))
			file.close()

		print(SUCCESS + '[+] Files Saved Successfully!' + RESET)

if __name__ == '__main__':
	prog = OutsiderRecon()
	prog.main()
