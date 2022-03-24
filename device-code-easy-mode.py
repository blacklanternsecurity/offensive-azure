#!/usr/bin/python3

import requests, json, time

get_device_code_endpoint = 'https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0'

win_core_management = 'https://management.core.windows.net'	# Windows Core Management
azure_management = 'https://management.azure.com'	# Azure Management (For use in Az [powershell, will not access AzAD cmdlets without also supplying graph token])
graph = 'https://graph.windows.net'	# Graph (For use with Az/AzureAD/AADInternals)
ms_graph = 'https://graph.microsoft.com'	# Microsoft Graph (Microsoft is moving towards this from graph in 2022)
ms_manage = 'https://enrollment.manage.microsoft.com' # Microsoft Manage
teams = 'https://api.spaces.skype.com' # Microsoft Teams
office_apps = 'https://officeapps.live.com' # Microsoft Office Apps
office_manage = 'https://manage.office.com' # Microsoft Office Management
outlook = 'https://outlook.office365.com' # Microsoft Outlook
substrate = 'https://substrate.office.com' # Substrate

# Set resource to one of the above resources you want to target
# You can always use a refresh token to request one of these later, 
# but if you just know what you want you can set it here:
resource = graph

post_data = {"resource": resource, "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c"}
start_time = time.time()

r = requests.post(get_device_code_endpoint, data=post_data)

response_json = json.loads(r.text)

device_code = response_json['device_code']

expires_in = response_json['expires_in']

print("\nMessage: " + response_json['message'] + '\n')

polling_endpoint = 'https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0'

poll_data = {
	"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
	"resource": resource,
	"code": device_code,
	"grant_type": "urn:ietf:params:oauth:grant-type:device_code"
}

dots = ""

while(True):
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
		break
	else:
		print(poll_json['error'] + dots + '   ', end='\r')
		if dots == "...":
			dots = ""
		else:
			dots = dots + "."
		if (int(current_time) - int(start_time)) > int(expires_in):
			print()
			print("Device Code Expired :(")
			break
		time.sleep(5)

