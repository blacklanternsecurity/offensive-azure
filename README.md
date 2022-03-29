<p align="center">
  <img src="https://user-images.githubusercontent.com/28767257/160513484-cb70370c-9fce-48d1-84ec-8b9ea3cf8e5a.png">
</p>

Collection of offensive tools targeting Microsoft Azure written in Python to be platform agnostic. The current list of tools can be found below with a brief description of their functionality.

- [`./Device_Code/device-code-easy-mode.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Device_Code)
  - Generates a code to be entered by the target user
  - Can be used for general token generation or during a phishing/social engineering campaign.
- [`./Access_Tokens/token-juggle.py`](https://github.com/blacklanternsecurity/offensive-azure/tree/main/Access_Tokens)
  - Takes in a refresh token in various ways and retrieves a new refresh token and an access token for the resource specified
