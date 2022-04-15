<p align="center">
  <img src="https://user-images.githubusercontent.com/28767257/160513484-cb70370c-9fce-48d1-84ec-8b9ea3cf8e5a.png">
</p>

Collection of offensive tools targeting Microsoft Azure written in Python to be platform agnostic. The current list of tools can be found below with a brief description of their functionality.

- [`./Device_Code/device_code_easy_mode.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Device_Code)
  - Generates a code to be entered by the target user
  - Can be used for general token generation or during a phishing/social engineering campaign.
- [`./Access_Tokens/token_juggle.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Access_Tokens)
  - Takes in a refresh token in various ways and retrieves a new refresh token and an access token for the resource specified
- [`./Outsider_Recon/outsider-recon.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Outsider_Recon)
  - Takes in a domain and enumerates as much information as possible about the tenant without requiring authentication 
- [`./User_Enum/user-enum.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/User_Enum)
  - Takes in a username or list of usernames and attempts to enumerate valid accounts using one of three methods
  - Can also be used to perform a password spray
