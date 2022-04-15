# device_code_easy_mode.py

Original inspiration comes directly from [Dr. Azure AD](https://twitter.com/DrAzureAD) and his [AADInternals](https://o365blog.com/aadinternals/) project. He developed a workflow in PowerShell for creating the device code flow authentication process that required you to stand up and supply an SMTP server for the cmdlet to interact on.

This didn't fit within our workflow at BLS so we decided to make a simpler tool that requests the device code for you, presents it to you, and polls the endpoint for any authentication events. It is up to you to stand up your own email infrastructure and conduct this phish in a successful way. Like the cmdlet in AADInternals, we use the application ID for Microsoft Office. This helps reassure the victim that they are interacting with a legitimate process.

You have the option to set the targeted resource within the script. Just choose from the URIs presented. For AzureAD and AADInternals usage, you'll want to use `GRAPH`. This is supposed to be going away sometime in April 2022 in favor of `MS_GRAPH`.

For use with all of the `Az` cmdlets, you'll need both `GRAPH` and `AZURE_MANAGEMENT` tokens. For this you'll need to use something like TokenTactics with your refresh token, for the time being, to request additional tokens once the device code flow authentication is completed.

We will have a similar python solution to TokenTactics in the near term.

## Requirements

`pip install -r ./requirements.txt`

## Usage

- `python3 ./device_code_easy_mode.py`
- Send your phish with the code your presented with as well as the `devicelogin` endpoint shown
- Wait for the target to perform the required steps
  - The device code authentication flow expires after 15 minutes, social engineering may help you prep your target
