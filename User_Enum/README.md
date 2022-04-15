# user-enum.py

```bash
usage: user-enum.py [-m login-method | -u username | -i input-list | -o outfile]

  =====================================================================================
  # This module will enumerate for valid user accounts in an Azure AD environment     #
  # There are three methods to enumerate with: login, autologon, normal                                                #
  #                                                                                   #
  # Default method: normal                                                            #
  #                                                                                   #
  # You may supply either a single username to test, or a user list                   #
  # Supplying a password will insert it into either the 'login' or 'autologon' method #
  # If the password is correct, account will be marked 'PWNED'                        #
  #                                                                                   #
  # Using the 'login' method will create failed authentication logs in Azure AD       #
  #                                                                                   #
  # Using the 'autologon' method will not create any logs, but is less accurate       #
  =====================================================================================

optional arguments:
  -h, --help            show this help message and exit
  -m <method>, --method <method>
                        The login method you would like to use (default is normal), select one of 'normal' 'login'
                        'autologon'
  -u <test@domain.com>, --username <test@domain.com>
                        The username you would like to test
  -i </path/to/usernames.txt>, --input-list </path/to/usernames.txt>
                        Text file containing usernames you want to test
  -p <password>, --password <password>
                        The password you want to spray with. Only works with 'login' and 'autologon' methods.
  -o </path/to/output/directory/>, --outfile </path/to/output/directory/>
                        Path to where you want to save your results
```
