# Access_Tokens

## token_juggle.py

Requests a new access token for a Microsoft/Azure resource using a refresh token.

Original inspiration comes directly from [rvrsh3ll](https://twitter.com/424f424f) and his [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) project. 

This script will attempt to load a refresh token from a REFRESH_TOKEN environment variable if none is passed with `-r` or `-R`.

After a successful refresh to a new access+refresh token pair, the response output will be saved to where you specify with `-o|--outfile`. If you do not specify an outfile, then it will be saved to `./YYYY-MM-DD_HH-MM-SS_<resource>_token.json`. These can be passed back to the script for further use.

## read_token.py

Reads an access token, parsing the various claims contained within it. Also attempts to validate the signature and tests for token expiration.

## Requirements

```
pip3 install -r requirements.txt
```

## Usage

### token_juggle.py

#### Using environment variable

```
export REFRESH_TOKEN=<refresh-token>
python3 token-juggle.py teams
```

#### Using a refresh token as input

```
python3 token_juggle.py outlook -r <refresh-token>
```

#### Using an already saved token response from this script

```
python3 token_juggle.py ms_graph -R <path-to-refresh-token.json>
```

#### Help

```bash
usage: token_juggle.py <resource> [-r 'refresh_token' | -R './path/to/refresh_token.json']

  =====================================================================================
  # Requests a new access token for a Microsoft/Azure resource using a refresh token. #
  #                                                                                   #
  # This script will attempt to load a refresh token from a REFRESH_TOKEN             #
  # environment variable if none is passed with '-r' or '-R'.                         #
  =====================================================================================

positional arguments:
  resource              The target Microsoft/Azure resource. Choose from the following: win_core_management,
                        azure_management, graph, ms_graph, ms_manage, teams, office_apps, office_manage, outlook,
                        substrate

optional arguments:
  -h, --help            show this help message and exit
  -r <refresh_token>, --refresh_token <refresh_token>
                        (string) The refresh token you would like to use.
  -R <refresh_token_file>, --refresh_token_file <refresh_token_file>
                        (string) A JSON file saved from this script containing the refresh token you would like to
                        use.
  -o <filename>, --outfile <filename>
                        (string) The path/filename of where you want the new token data (json object) saved. If not
                        supplied, script defaults to "./YYYY-MM-DD_HH-MM-SS_<resource>_token.json"
```

### read_token.py

#### Help

```bash
usage: read_token.py [-t|--token <access_token>]

        ==========================================================
        #                                                        #
        #  Reads an access token for a Microsoft/Azure resource  #
        #                                                        #
        ==========================================================

optional arguments:
  -h, --help            show this help message and exit
  -t <access_token>, --token <access_token>
                        The token you would like to read
```