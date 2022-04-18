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
import json
import time
import requests

GET_DEVICE_CODE_ENDPOINT = \
	'https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0'

# Windows Core Management
WIN_CORE_MANAGEMENT = 'https://management.core.windows.net'

# Azure Management
# For use in Az [powershell, will not access AzAD cmdlets without also supplying graph token]
AZURE_MANAGEMENT = 'https://management.azure.com'

# Graph (For use with Az/AzureAD/AADInternals)
GRAPH = 'https://graph.windows.net'

# Microsoft Graph (Microsoft is moving towards this from graph in 2022)
MS_GRAPH = 'https://graph.microsoft.com'

# Microsoft Manage
MS_MANAGE = 'https://enrollment.manage.microsoft.com'

# Microsoft Teams
TEAMS = 'https://api.spaces.skype.com'

# Microsoft Office Apps
OFFICE_APPS = 'https://officeapps.live.com'

# Microsoft Office Management
OFFICE_MANAGE = 'https://manage.office.com'

# Microsoft Outlook
OUTLOOK = 'https://outlook.office365.com'

# Substrate
SUBSTRATE = 'https://substrate.office.com'

# Set RESOURCE to one of the above resources you want to target
# You can always use a refresh token to request one of these later,
# but if you just know what you want you can set it here:
RESOURCE = GRAPH

def main():
	"""Main runner function of the module. Handles the entire request-response transaction"""
	post_data = {"resource": RESOURCE, "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c"}
	start_time = time.time()

	request = requests.post(GET_DEVICE_CODE_ENDPOINT, data=post_data)

	response_json = json.loads(request.text)

	device_code = response_json['device_code']

	expires_in = response_json['expires_in']

	print("\nMessage: " + response_json['message'] + '\n')

	polling_endpoint = 'https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0'

	poll_data = {
		"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
		"resource": RESOURCE,
		"code": device_code,
		"grant_type": "urn:ietf:params:oauth:grant-type:device_code"
	}

	dots = ""

	unfinished = True

	while unfinished:
		current_time = time.time()
		poll = requests.post(polling_endpoint, data=poll_data)
		status_code = poll.status_code
		poll_json = json.loads(poll.text)
		if status_code == 200:
			print()
			print("Token Type: " + poll_json['token_type'])
			print("Scope: " + poll_json['scope'])
			print("Expires In: " + poll_json['expires_in'])
			print("Expires On: " + poll_json['expires_on'])
			print("Not Before: " + poll_json['not_before'])
			print("Resource: " + poll_json['resource'])
			print("Acess Token:\n" + poll_json['access_token'])
			print("Refresh Token:\n" + poll_json['refresh_token'])
			print("ID Token:\n" + poll_json['id_token'])
			unfinished = False
		else:
			print(poll_json['error'] + dots + '   ', end='\r')
			if dots == "...":
				dots = ""
			else:
				dots = dots + "."
			if (int(current_time) - int(start_time)) > int(expires_in):
				print()
				print("Device Code Expired :(")
				unfinished = False
			time.sleep(5)
	sys.exit()

if __name__ == '__main__':
	main()
	sys.exit()
