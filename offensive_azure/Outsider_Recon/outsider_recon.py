#!/usr/bin/python3

"""
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
"""

import argparse
import json
import sys
import time
import xml.etree.ElementTree as ET

import colorama
import dns.rcode
import dns.resolver
import requests
import whois


class OutsiderRecon:
    """
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
    """

    @staticmethod
    def enumerate_domain_info(domains, login_infos):
        """Takes in list of domains and login information, returns domain details"""
        domain_info = {}
        for domain in domains:
            domain_info[domain] = {}

            # Check if domain has SSO emabled
            domain_info[domain]["sso"] = False
            try:
                if login_infos[domain]["Desktop SSO Enabled"] == "True":
                    domain_info[domain]["sso"] = True
            except KeyError:
                pass

            # Check for Namespace
            try:
                domain_info[domain]["type"] = login_infos[domain]["Namespace Type"]
            except KeyError:
                domain_info[domain]["type"] = "Unknown"

            # Check for STS
            try:
                domain_info[domain]["sts"] = login_infos[domain]["Authentication URL"]
            except KeyError:
                domain_info[domain]["sts"] = ""

            # Check for WHOIS
            domain_info[domain]["whois"] = False
            try:
                whois_response = whois.query(domain)
                domain_info[domain]["whois"] = bool(whois_response.name)
            except Exception as e:
                pass

            # Check if DNS Name resolves
            try:
                dns_response = dns.resolver.resolve(domain)
                if dns.rcode.to_text(dns_response.response.rcode()) == "NOERROR":
                    domain_info[domain]["dns"] = True
                else:
                    domain_info[domain]["dns"] = False
                    domain_info[domain]["cloudmx"] = False
                    domain_info[domain]["cloudspf"] = False
                    domain_info[domain]["dmarc"] = False
                    continue
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                domain_info[domain]["dns"] = False
                domain_info[domain]["cloudmx"] = False
                domain_info[domain]["cloudspf"] = False
                domain_info[domain]["dmarc"] = False
                continue

            # Check for CloudMX
            try:
                domain_info[domain]["cloudmx"] = False
                dns_response = dns.resolver.resolve(domain, "MX")
                for answer in dns_response:
                    if "mail.protection.outlook.com" in str(answer):
                        domain_info[domain]["cloudmx"] = True
                        break
            except dns.exception.DNSException:
                pass
            # Check for CloudSPF
            try:
                domain_info[domain]["cloudspf"] = False
                dns_response = dns.resolver.resolve(domain, "TXT")
                for answer in dns_response:
                    if "include:spf.protection.outlook.com" in str(answer):
                        domain_info[domain]["cloudspf"] = True
                        break
            except dns.exception.DNSException:
                pass
            # Check for DMARC
            try:
                domain_info[domain]["dmarc"] = False
                dns_response = dns.resolver.resolve("_dmarc." + domain, "TXT")
                for answer in dns_response:
                    if "v=DMARC1" in str(answer):
                        domain_info[domain]["dmarc"] = True
                        break
            except dns.exception.DNSException:
                pass

        return domain_info

    @staticmethod
    def enumerate_tenant_id(openid_config):
        """Given an openid_config, will return the tenant ID"""
        return openid_config["authorization_endpoint"].split("/")[3]

    @staticmethod
    def enumerate_login_info(domain, username):
        """Given a domain and optional username, will return the authentication related info"""
        results = {}

        user = username + "@" + domain

        endpoint1 = (
            f"https://login.microsoftonline.com/common/userrealm/{user}?api-version=1.0"
        )
        endpoint2 = (
            f"https://login.microsoftonline.com/common/userrealm/{user}?api-version=2.0"
        )
        endpoint3 = f"https://login.microsoftonline.com/GetUserRealm.srf?login={user}"
        endpoint4 = "https://login.microsoftonline.com/common/GetCredentialType"

        body = {
            "username": user,
            "isOtherIdpSupported": "true",
            "checkPhones": "true",
            "isRemoteNGCSupported": "false",
            "isCookieBannerShown": "false",
            "isFidoSupported": "false",
            "originalRequest": "",
        }

        json_data = json.dumps(body)

        headers4 = {
            "Content-Type": "application/json; charset=utf-8",
        }

        user_realm_json1 = requests.get(endpoint1).json()
        user_realm_json2 = requests.get(endpoint2).json()
        user_realm_json3 = requests.get(endpoint3).json()
        user_realm_json4 = requests.post(
            endpoint4, headers=headers4, data=json_data
        ).json()

        try:
            results["Account Type"] = user_realm_json1["account_type"]
        except KeyError:
            pass
        try:
            results["Namespace Type"] = user_realm_json2["NameSpaceType"]
        except KeyError:
            pass
        try:
            results["Domain Name"] = user_realm_json3["DomainName"]
        except KeyError:
            pass
        try:
            results["Cloud Instance"] = user_realm_json1["cloud_instance_name"]
        except KeyError:
            pass
        try:
            results["Cloud Instance Audience URN"] = user_realm_json1[
                "cloud_audience_urn"
            ]
        except KeyError:
            pass
        try:
            results["Federation Brand Name"] = user_realm_json3["FederationBrandName"]
        except KeyError:
            pass
        try:
            results["State"] = user_realm_json3["State"]
        except KeyError:
            pass
        try:
            results["User State"] = user_realm_json3["UserState"]
        except KeyError:
            pass
        try:
            results["Exists"] = user_realm_json4["IfExistsResult"]
        except KeyError:
            pass
        try:
            results["Throttle Status"] = user_realm_json4["ThrottleStatus"]
        except KeyError:
            pass
        try:
            results["Pref Credential"] = user_realm_json4["Credentials"][
                "PrefCredential"
            ]
        except KeyError:
            pass
        try:
            results["Has Password"] = user_realm_json4["Credentials"]["HasPassword"]
        except KeyError:
            pass
        try:
            results["Domain Type"] = user_realm_json4["EstsProperties"]["DomainType"]
        except KeyError:
            pass
        try:
            results["Federation Protocol"] = user_realm_json1["federation_protocol"]
        except KeyError:
            pass
        try:
            results["Federation Metadata URL"] = user_realm_json1[
                "federation_metadata_url"
            ]
        except KeyError:
            pass
        try:
            results["Federation Active Authentication URL"] = user_realm_json1[
                "federation_active_auth_url"
            ]
        except KeyError:
            pass
        try:
            results["Authentication URL"] = user_realm_json2["AuthUrl"]
        except KeyError:
            pass
        try:
            results["Consumer Domain"] = user_realm_json2["ConsumerDomain"]
        except KeyError:
            pass
        try:
            results["Federation Global Version"] = user_realm_json3[
                "FederationGlobalVersion"
            ]
        except KeyError:
            pass
        try:
            results["Desktop SSO Enabled"] = user_realm_json4["EstsProperties"][
                "DesktopSsoEnabled"
            ]
        except KeyError:
            pass

        return results

    @staticmethod
    def enumerate_openid(domain):
        """Given a domain, will return the openid configuration information"""
        endpoint = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"

        openid_config_json = requests.get(endpoint).json()

        return openid_config_json

    @staticmethod
    def enumerate_tenant_domains(domain, user_agent="AutodiscoverClient"):
        """Given a domain and optional user_agent, returns domains under shared tenant"""
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"http://schemas.microsoft.com/exchange/2010'
            '/Autodiscover/Autodiscover/GetFederationInformation"',
            "User-Agent": user_agent,
        }

        xml = f"""<?xml version="1.0" encoding="utf-8"?>
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
</soap:Envelope>"""

        endpoint = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

        # Get Tenant Domains with Supplied Domain
        # Returns a SOAP Envelope object
        # Loops until we receive valid data
        proceed = False
        while not proceed:
            tenant_domains = requests.post(endpoint, data=xml, headers=headers)
            if tenant_domains.status_code == 421:
                return None
            tenant_domains.encoding = "utf-8"
            try:
                xml_response = ET.fromstring(str(tenant_domains.content, "utf-8"))
                proceed = True
            except ET.ParseError:
                continue

        domains = []

        for i in xml_response[1][0][0][3]:
            domains.append(i.text)

        return domains

    def main(self):
        """Runner method"""
        # Set up our colors
        colorama.init()
        success = colorama.Fore.GREEN
        danger = colorama.Fore.RED
        warning = colorama.Fore.YELLOW
        reset = colorama.Style.RESET_ALL

        description = """
  =====================================================================================
  # This module will enumerate all available information for a given target domain    #
  # within an Azure tenant. This does not require any level of pre-existing access.   #
  =====================================================================================
"""

        arg_parser = argparse.ArgumentParser(
            prog="outsider_recon.py",
            usage=success
            + "%(prog)s"
            + warning
            + " <domain>"
            + reset
            + " [-o|--outfile <path-to-file>] [-u|--user <user>]",
            description=description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        arg_parser.add_argument(
            "Domain",
            metavar="domain",
            type=str,
            help="The target Microsoft/Azure domain",
        )
        arg_parser.add_argument(
            "-o",
            "--outfile-path",
            metavar="<path>",
            dest="outfile_path",
            type=str,
            help="(string) The path where you want the recon data (json object) saved.\n"
            "If not supplied, module defaults to the current directory",
            required=False,
        )
        arg_parser.add_argument(
            "-f",
            "--filename",
            metavar="<filename>",
            dest="filename",
            type=str,
            help="(string) The filename you want the recon data (json object) saved as.",
            required=False,
        )
        arg_parser.add_argument(
            "-sf",
            "--single-file",
            dest="single_file",
            help="(boolean) Whether or not to output all results to a single file. If not supplied, module defaults to False",
            required=False,
            action="store_true",
        )
        arg_parser.add_argument(
            "-s",
            "--silent",
            dest="silent",
            help="(boolean) Whether or not to suppress all output to stdout. If not supplied, module defaults to False",
            required=False,
            action="store_true",
        )
        arg_parser.add_argument(
            "-u",
            "--user",
            metavar="<username>",
            dest="user",
            type=str,
            help="(string) The user you want to use during enumeration. Do not include the"
            ' domain.\nIf not supplied, module defaults to "none"',
            required=False,
        )

        args = arg_parser.parse_args()

        outfile_prefix = time.strftime("%Y-%m-%d_%H-%M-%S_" + args.Domain + "_")

        if args.filename and not args.single_file:
            print(
                "You must supply the -sf/--single-file flag to use the -f/--filename flag"
            )
            exit(1)

        # Set a default path if none is given
        path = args.outfile_path
        if path is None:
            path = "./"
        elif path[-1] != "/":
            path = path + "/"

        # Set a default user if none is given
        user = args.user
        if user is None:
            user = "none"
        else:
            user = user.split("@")[0]

        # Enumerating all domains for the tenant the passed in domain belongs to
        if not args.silent:
            print(warning + "Enumerating Other Domains Within Tenant" + reset + "\n")
        domains_found = self.enumerate_tenant_domains(args.Domain)
        if domains_found is None:
            print(
                danger + "It doesn't look like this is a domain in Azure."
                " Check your domain or try something else."
            )
            sys.exit()
        if not args.silent:
            for domain_found in domains_found:
                print(success + "[+] " + reset + domain_found)
            print()

        # Enumerating the openid configuration for the tenant
        if not args.silent:
            print(
                warning + "Enumerating OpenID Configuration for Tenant" + reset + "\n"
            )
        openid_config = self.enumerate_openid(args.Domain)
        if not args.silent:
            for elem in openid_config:
                print(
                    (
                        success + elem + reset + ":\t" + str(openid_config[elem])
                    ).expandtabs(50)
                )
            print()

        # Enumerating the login information for each domain discovered
        login_infos = {}
        if not args.silent:
            print(warning + "Enumerating User Login Information" + reset + "\n")
        for domain_found in domains_found:
            user_realm_json = self.enumerate_login_info(args.Domain, user)
            login_infos[domain_found] = user_realm_json
            if not args.silent:
                print(warning + "[+] " + domain_found + ":" + reset)
                print(warning + "========================" + reset)
                for key, value in user_realm_json.items():
                    print((success + key + reset + ":\t" + str(value)).expandtabs(50))
                print(warning + "========================" + reset + "\n")
        print()

        # Enumerate the tenant ID
        if not args.silent:
            print(warning + "Tenant ID" + reset + "\n")
        tenant_id = self.enumerate_tenant_id(openid_config)
        if not args.silent:
            print(success + "[+] " + reset + tenant_id)
            print()

        # Enumerate Domain Information (DNS, CLOUDMX, CLOUDSPF, DMARC, Identity Management, STS, SSO)
        if not args.silent:
            print(warning + "Enumerating Domain Information" + reset + "\n")
        domain_info = self.enumerate_domain_info(domains_found, login_infos)
        if not args.silent:
            for domain_name, domain_data in domain_info.items():
                print(warning + "[+] " + domain_name + ":" + reset)
                print(warning + "========================" + reset)
                for key, value in domain_data.items():
                    print((success + key + reset + ":\t" + str(value)).expandtabs(24))
                print(warning + "========================" + reset + "\n")

        # Save our results to files

        # Save Domain List
        if not args.single_file:
            with open(
                path + outfile_prefix + "domain_list.txt", "w+", encoding="UTF-8"
            ) as file:
                for dom in domains_found:
                    file.write(dom + "\n")
                file.close()

            # Save Tenant OpenID Configuration
            with open(
                path + outfile_prefix + "tenant_openid_config.json",
                "w+",
                encoding="UTF-8",
            ) as file:
                file.write(json.dumps(openid_config))
                file.close()

            # Save Domain Login Information
            with open(
                path + outfile_prefix + "domain_login_information.json",
                "w+",
                encoding="UTF-8",
            ) as file:
                file.write(json.dumps(login_infos))
                file.close()

            # Save Tenant ID
            with open(
                path + outfile_prefix + "tenant_id.txt", "w+", encoding="UTF-8"
            ) as file:
                file.write(tenant_id)
                file.close()

            # Save Domain Information
            with open(
                path + outfile_prefix + "domain_information.json",
                "w+",
                encoding="UTF-8",
            ) as file:
                file.write(json.dumps(domain_info))
                file.close()

        # Save Single File
        else:
            if args.filename:
                outfile = path + args.filename
            else:
                outfile = path + outfile_prefix + "outsider_recon.json"

            with open(outfile, "w+", encoding="UTF-8") as file:
                file.write(
                    json.dumps(
                        {
                            "domains": domains_found,
                            "openid_config": openid_config,
                            "login_info": login_infos,
                            "tenant_id": tenant_id,
                            "domain_info": domain_info,
                        },
                        indent=4,
                        sort_keys=True,
                    )
                )
                # file.close()

        # if not args.silent:
        #     print(success + "[+] Files Saved Successfully!" + reset)


def runner():
    """Runner function"""
    prog = OutsiderRecon()
    prog.main()
    sys.exit()


if __name__ == "__main__":
    runner()
    sys.exit()
