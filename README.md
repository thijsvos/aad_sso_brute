# **AzureAD SSO brute**
Python tool to brute force against an AzureAD SSO endpoint.

## Installation

First install the requirements to run the script.
```
pip install -r requirements.txt
```

## Basic Usage

```
python3 main.py usernames.txt passwords.txt --stop_brute
[INFO]: Starting brute force..
[INFO]: Finishing up brute forcing.. found 1 valid credentials.
[SUCCESS]: test@epic-company.tld - EpicPassword1337
```

## Help overview

```
Brute force tool to enumerate emails and spray passwords.

positional arguments:
  username_file         File containing usernames (e.g. 'first.last@contoso.com' or 'admin-first.last@contoso.onmicrosoft.com::tennant-name.com').
  password_file         File containing passwords.

optional arguments:
  -h, --help            show this help message and exit
  --timeout TIMEOUT     Timeout period for every try/request.
  -v, --verbose         Verbose output.
  --guid GUID           Device guid for the SSO request.
  -ps PASSWORD_SLEEP, --password_sleep PASSWORD_SLEEP
                        Sleep time in seconds between passwords.
  --continue_brute      Brute force continues after locked out accounts were found.
  --continue_but_skip_lockedouts
                        Brute force continues after locked out accounts were found, but skips the accounts that were locked out.
  --stop_brute          Brute force stops after a locked out account was found.
```
