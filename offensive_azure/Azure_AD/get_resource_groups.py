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
	#  Uses Azure Resource Management API to pull a full     #
	#  list of resource groups.                              #
	#                                                        #
	#  If no ARM token or refresh_token is supplied,         #
	#  module will look in the REFRESH_TOKEN environment     #
	#  variable and request the ARM token                    #
	#                                                        #
	#  Outputs a raw json output file, and a json file       #
	#  compatible with BloodHound                            #
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
ENDPOINT_BASE = 'https://management.azure.com/subscriptions/'
ENDPOINT_RSGS = '/resourcegroups?api-version=2021-04-01'
ENDPOINT_SUBS = 'https://management.azure.com/subscriptions?api-version=2020-01-01'

# For use when requesting new access tokens with refresh token
URI = 'https://login.microsoftonline.com/Common/oauth2/token'
CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'

# User agent to use with requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0'

def main():
	"""Runner method"""
	arg_parser = argparse.ArgumentParser(
		prog='get_resource_groups.py',
		usage=SUCCESS + '%(prog)s' + RESET + \
			' [-t|--arm_token <arm_token>]' + \
			' [-r|--refresh_token <refresh_token>]',
		description=DESCRIPTION,
		formatter_class=argparse.RawDescriptionHelpFormatter)
	arg_parser.add_argument(
		'-t',
		'--arm_token',
		metavar='<arm_token>',
		dest='arm_token',
		type=str,
		help='The ARM token you would like to use',
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
			'the resource group data saved.'\
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
	outfile_raw_json = outfile_path_base + 'resource_groups_raw.json'
	outfile_bloodhound = outfile_path_base + 'resource_groups_bloodhound.json'

	# Check to see if any graph or refresh token is given in the arguments
	# If both are given, will use graph token
	# If no token given, will check for a refresh token file
	# If no arguments are given, will look in the REFRESH_TOKEN environment variable
	if args.refresh_token is None and args.arm_token is None and \
		args.refresh_token_file is None:
		try:
			refresh_token = os.environ['REFRESH_TOKEN']
		except KeyError:
			print(DANGER, '\n\tNo refresh token found.\n', RESET)
			arg_parser.print_help()
			sys.exit()
	elif args.refresh_token is None and args.arm_token is None:
		path = args.refresh_token_file
		try:
			with open(path, encoding='UTF-8') as json_file:
				json_file_data = json.load(json_file)
				json_file.close()
		except OSError as error:
			print(str(error))
			sys.exit()
		refresh_token = json_file_data['refresh_token']
	elif args.arm_token is not None:
		arm_token = args.arm_token
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
			'resource': 'https://management.azure.com',
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
		arm_token = json_data['access_token']

	# Grabbing available subscriptions
	headers = {
		'Authorization': 'Bearer ' + arm_token
	}
	subs_response = requests.get(ENDPOINT_SUBS, headers=headers).json()
	raw_json_data_subs = {
		'value': subs_response['value']
	}
	try:
		next_link = subs_response['nextLink']
	except KeyError:
		next_link = None
	while next_link:
		subs_response = requests.get(next_link, headers=headers).json()
		for sub in subs_response['value']:
			raw_json_data_subs['value'].append(sub)
		try:
			next_link = subs_response['nextLink']
		except KeyError:
			next_link = None

	# We have our subs, now we need to grab the resource groups within each
	raw_json_data_rsg = {'value': []}
	for sub in raw_json_data_subs['value']:
		sub_id = sub['subscriptionId']
		resource_group_response = requests.get(ENDPOINT_BASE + sub_id + ENDPOINT_RSGS,
												headers=headers).json()
		for rsg in resource_group_response['value']:
			raw_json_data_rsg['value'].append(rsg)
		try:
			next_link = resource_group_response['nextLink']
		except KeyError:
			next_link = None
		while next_link:
			resource_group_response = requests.get(next_link, headers=headers).json()
			for rsg in resource_group_response['value']:
				raw_json_data_rsg['value'].append(rsg)
			try:
				next_link = resource_group_response['nextLink']
			except KeyError:
				next_link = None

	# We should have our complete list of resource groups now
	count = len(raw_json_data_rsg['value'])

	# Process raw data
	bloodhound_json_data = {
		'meta': {
			'count': count,
			'type': 'azresourcegroups',
			'version': 4
		},
		'data': []
	}
	for rsg in raw_json_data_rsg['value']:
		sub_id = rsg['id'].split('/')[2]
		bloodhound_json_data['data'].append({
			'ResourceGroupName': rsg['name'],
			'SubscriptionID': sub_id,
			'ResourceGroupID': rsg['id']
		})
		for prop, val in rsg.items():
			if val is not None:
				print(f'{SUCCESS}{prop}{RESET}:\t{str(val)}'.expandtabs(32))
		print()

	# Writing out raw data
	print(f'{SUCCESS}[+]{RESET} Writing raw data to {outfile_raw_json}')
	with open(outfile_raw_json, 'w+', encoding='UTF-8') as raw_out:
		json.dump(raw_json_data_rsg, raw_out, indent=4)

	# Writing out bloodhound data
	print(f'{SUCCESS}[+]{RESET} Writing bloodhound data to {outfile_bloodhound}')
	with open(outfile_bloodhound, 'w+', encoding='UTF-8') as bloodhound_out:
		json.dump(bloodhound_json_data, bloodhound_out, indent=4)

if __name__ == '__main__':
	main()
	sys.exit()
