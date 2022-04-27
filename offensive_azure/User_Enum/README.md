# user_enum.py

```bash
usage: user_enum.py [-m login-method | -u username | -i input-list | -o outfile]

  =====================================================================================
  # This module will enumerate for valid user accounts in an Azure AD environment     #
  # There are five methods to enumerate with: login, sso, normal, onedrive, lists     #
  #                                                                                   #
  # Default method: normal                                                            #
  #                                                                                   #
  # You may supply either a single username to test, or a user list                   #
  # Supplying a password will insert it into either the 'login' or 'sso' method       #
  #                                                                                   #
  # If the password is correct, and there are no other obstacles, then the account    #
  # will be marked 'PWNED'                                                            #
  #                                                                                   #
  # Using the 'login' method will create failed authentication logs in Azure AD       #
  #                                                                                   #
  # Using the 'sso' 'lists' or 'onedrive' methods will not create any logs,           #
  # but is less accurate                                                              #
  =====================================================================================

optional arguments:
  -h, --help            show this help message and exit
  -m <method>, --method <method>
                        The login method you would like to use (default is normal), select one of 'normal' 'onedrive' 'lists' 'login' 'sso'
  -u <test@domain.com>, --username <test@domain.com>
                        The username you would like to test
  -i </path/to/usernames.txt>, --input-list </path/to/usernames.txt>
                        Text file containing usernames you want to test
  -p <password>, --password <password>
                        The password you want to spray with. Only works with 'login' and 'sso' methods.
  -o </path/to/output/directory/>, --outfile </path/to/output/directory/>
                        Path to where you want to save your results
```
