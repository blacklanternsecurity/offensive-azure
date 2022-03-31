#!/usr/bin/python3

import os, requests, sys, argparse, colorama, time, json, dns.resolver, dns.rcode
import xml.etree.ElementTree as ET

class Outsider_Recon:

	def enumerate_domain_info(self, domains, login_infos):
		domain_info = {}
		for domain in domains:
			domain_info[domain] = {}

			# Check if domain has SSO emabled
			domain_info[domain]['sso'] = False
			try:
				if login_infos[domain]['Desktop SSO Enabled'] == 'True':
					domain_info[domain]['sso'] = True
			except:
				None

			# Check for Namespace
			try:
				domain_info[domain]['type'] = login_infos[domain]['Namespace Type']
			except:
				domain_info[domain]['type'] = 'Unknown'

			# Check for STS
			try:
				domain_info[domain]['sts'] = login_infos[domain]['Authentication URL']
			except:
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
			except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as na:
				domain_info[domain]['dns'] = False
				domain_info[domain]['cloudmx'] = False
				domain_info[domain]['cloudspf'] = False
				domain_info[domain]['dmarc'] = False
				continue

			# Check for CloudMX
			try:
				domain_info[domain]['cloudmx'] = False
				dns_response = dns.resolver.resolve(domain, 'MX')
				for a in dns_response:
					if 'mail.protection.outlook.com' in str(a):
						domain_info[domain]['cloudmx'] = True
						break
			except Exception as e:
				None
			# Check for CloudSPF
			try:
				domain_info[domain]['cloudspf'] = False
				dns_response = dns.resolver.resolve(domain, 'TXT')
				for a in dns_response:
					if 'include:spf.protection.outlook.com' in str(a):
						domain_info[domain]['cloudspf'] = True
						break
			except Exception as e:
				None
			# Check for DMARC
			try:
				domain_info[domain]['dmarc'] = False
				dns_response = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
				for a in dns_response:
					if 'v=DMARC1' in str(a):
						domain_info[domain]['dmarc'] = True
						break
			except Exception as e:
				None
				
		return domain_info

	def enumerate_tenant_id(self, openid_config):

		return openid_config['authorization_endpoint'].split('/')[3]


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
		except KeyError as ke:
			None
		try:
			results['Namespace Type'] = user_realm_json2['NameSpaceType']
		except KeyError as ke:
			None
		try:
			results['Domain Name'] = user_realm_json3['DomainName']
		except KeyError as ke:
			None
		try:
			results['Cloud Instance'] = user_realm_json1['cloud_instance_name']
		except KeyError as ke:
			None
		try:
			results['Cloud Instance Audience URN'] = user_realm_json1['cloud_audience_urn']
		except KeyError as ke:
			None
		try:
			results['Federation Brand Name'] = user_realm_json3['FederationBrandName']
		except KeyError as ke:
			None
		try:
			results['State'] = user_realm_json3['State']
		except KeyError as ke:
			None
		try:
			results['User State'] = user_realm_json3['UserState']
		except KeyError as ke:
			None
		try:
			results['Exists'] = user_realm_json4['IfExistsResult']
		except KeyError as ke:
			None
		try:
			results['Throttle Status'] = user_realm_json4['ThrottleStatus']
		except KeyError as ke:
			None
		try:
			results['Pref Credential'] = user_realm_json4['Credentials']['PrefCredential']
		except KeyError as ke:
			None
		try:
			results['Has Password'] = user_realm_json4['Credentials']['HasPassword']
		except KeyError as ke:
			None
		try:
			results['Domain Type'] = user_realm_json4['EstsProperties']['DomainType']
		except KeyError as ke:
			None
		try:
			results['Federation Protocol'] = user_realm_json1['federation_protocol']
		except KeyError as ke:
			None
		try:
			results['Federation Metadata URL'] = user_realm_json1['federation_metadata_url']
		except KeyError as ke:
			None
		try:
			results['Federation Active Authentication URL'] = user_realm_json1['federation_active_auth_url']
		except KeyError as ke:
			None
		try:
			results['Authentication URL'] = user_realm_json2['AuthUrl']
		except KeyError as ke:
			None
		try:
			results['Consumer Domain'] = user_realm_json2['ConsumerDomain']
		except KeyError as ke:
			None
		try:
			results['Federation Global Version'] = user_realm_json3['FederationGlobalVersion']
		except KeyError as ke:
			None
		try:
			results['Desktop SSO Enabled'] = user_realm_json4['EstsProperties']['DesktopSsoEnabled']
		except KeyError as ke:
			None

		return results

	def enumerate_openid(self, domain):

		endpoint = 'https://login.microsoftonline.com/%s/.well-known/openid-configuration' % (domain)

		openid_config_json = requests.get(endpoint).json()

		return openid_config_json


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
		while(proceed == False):
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


	def main(self):
		# Set up our colors
		colorama.init()
		success = colorama.Fore.GREEN
		danger = colorama.Fore.RED
		warning = colorama.Fore.YELLOW
		reset = colorama.Style.RESET_ALL

		description = '''
  =====================================================================================
  # This module will enumerate all available information for a given target domain    #
  # within an Azure tenant. This does not require any level of pre-existing access.   #
  =====================================================================================
'''

		arg_parser = argparse.ArgumentParser(prog='outsider-recon.py', 
											 usage=success + '%(prog)s' + warning + ' <domain>' + reset + ' [-o|--outfile <path-to-file>] [-u|--user <user>]',
											 description=description,
											 formatter_class=argparse.RawDescriptionHelpFormatter
											 )
		arg_parser.add_argument('Domain',
								metavar='domain',
								type=str,
								help='The target Microsoft/Azure domain')
		arg_parser.add_argument('-o',
								'--outfile-path',
								metavar='<path>',
								dest='outfile_path',
								type=str,
								help='(string) The path where you want the recon data (json object) saved.\nIf not supplied, module defaults to the current directory',
								required=False)
		arg_parser.add_argument('-u',
								'--user',
								metavar='<username>',
								dest='user',
								type=str,
								help='(string) The user you want to use during enumeration. Do not include the domain.\nIf not supplied, module defaults to "none"',
								required=False)

		args = arg_parser.parse_args()

		outfile_prefix = time.strftime('%Y-%m-%d_%H-%M-%S_' + args.Domain + '_')

		# Set a default path if none is given
		path = args.outfile_path
		if path == None:
			path = './'
		elif path[-1] != '/':
			path = path + '/'

		# Set a default user if none is given
		user = args.user
		if user == None:
			user = 'none'
		
		# Enumerating all domains for the tenant the passed in domain belongs to
		print(warning + 'Enumerating Other Domains Within Tenant' + reset + '\n')
		domains_found = self.enumerate_tenant_domains(args.Domain)
		if domains_found == None:
			print(danger + 'It doesn\'t look like this is a domain in Azure. Check your domain or try something else.')
			sys.exit()
		for domain_found in domains_found:
			print(success + '[+] ' + reset + domain_found)
		print()
		
		# Enumerating the openid configuration for the tenant
		print(warning + 'Enumerating OpenID Configuration for Tenant' + reset + '\n')
		openid_config = self.enumerate_openid(args.Domain)
		for elem in openid_config:
			print((success + elem + reset + ':\t' + str(openid_config[elem])).expandtabs(50))
		print()
		
		# Enumerating the login information for each domain discovered
		login_infos = {}
		print(warning + 'Enumerating User Login Information' + reset + '\n')
		for domain_found in domains_found:
			user_realm_json = self.enumerate_login_info(args.Domain, user)
			login_infos[domain_found] = user_realm_json
			print(warning + '[+] ' + domain_found + ":" + reset)
			print(warning + '========================' + reset)
			for elem in user_realm_json:
				print((success + elem + reset + ":\t" + str(user_realm_json[elem])).expandtabs(50))
			print(warning + '========================' + reset + '\n')
		print()

		# Enumerate the tenant ID
		print(warning + 'Tenant ID' + reset + '\n')
		tenant_id = self.enumerate_tenant_id(openid_config)
		print(success + '[+] ' + reset + tenant_id)
		print()

		# Enumerate Domain Information (DNS, CLOUDMX, CLOUDSPF, DMARC, Identity Management, STS, SSO)
		print(warning + 'Enumerating Domain Information' + reset + '\n')
		domain_info = self.enumerate_domain_info(domains_found, login_infos)
		for domain_name in domain_info:
			print(warning + '[+] ' + domain_name + ":" + reset)
			print(warning + '========================' + reset)
			for key, value in domain_info[domain_name].items():
				print((success + key + reset + ":\t" + str(value)).expandtabs(24))
			print(warning + '========================' + reset + '\n')

		# Save our results to files
		
		## Save Domain List
		f = open(path + outfile_prefix + 'domain_list.txt', 'w+')
		for dom in domains_found:
			f.write(dom + '\n')
		f.close()

		## Save Tenant OpenID Configuration
		f = open(path + outfile_prefix + 'tenant_openid_config.json', 'w+')
		f.write(json.dumps(openid_config))
		f.close()

		## Save Domain Login Information
		f = open(path + outfile_prefix + 'domain_login_information.json', 'w+')
		f.write(json.dumps(login_infos))
		f.close()

		## Save Tenant ID
		f = open(path + outfile_prefix + 'tenant_id.txt', 'w+')
		f.write(tenant_id)
		f.close()

		## Save Domain Information
		f = open(path + outfile_prefix + 'domain_information.json', 'w+')
		f.write(json.dumps(domain_info))
		f.close()

		print(success + '[+] Files Saved Successfully!' + reset)

if __name__ == '__main__':
	prog = Outsider_Recon()
	prog.main()