import argparse
import requests
import os
from datetime import datetime
import hashlib

verbose = False  

'''
def list_file_urls(token, channel):
    url = f"https://slack.com/api/files.list?channel={channel}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    data = response.json()
    if response.status_code != 200:
        print(f"Error {response.status_code} - {data.get('error', 'Unknown error')} for channel {channel}")
        return []

    if data.get("ok"):
        return [file_info["url_private"] for file_info in data["files"]]
    else:
        print(f"Error retrieving file URLs for channel {channel}: {data.get('error', 'Unknown error')}")
        return []

def download_files(token, urls):
    for url in urls:
        response = requests.get(url, headers={"Authorization": f"Bearer {token}"}, stream=True)
        if response.status_code == 200:
            filename = url.split("/")[-1]
            with open(filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Downloaded: {filename}")
        else:
            print(f"Error downloading: {url}")
'''

def list_file_urls(token, channel):
    url = "https://slack.com/api/files.list"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    data = response.json()
    if data.get("ok"):
        return [file_info["url_private"] for file_info in data["files"]]
    else:
        print(f"Error retrieving file URLs for channel {channel}: {data.get('error', 'Unknown error')}")
        return []


def download_files(token, urls, output_directory=None, verbose=False):
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    for url in urls:
        response = requests.get(url, headers={"Authorization": f"Bearer {token}"}, stream=True)
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



def list_files(token, verbose=False):   

    channels = list_channels(token)


    all_file_urls = []
    for channel in channels:
        channel_id = channel['id']
        try:
            file_urls = list_file_urls(token, channel_id)
            all_file_urls.extend(file_urls)
        except Exception as e:
            print(f"Error retrieving file URLs for channel {channel_id}: {str(e)}")
    return all_file_urls



def list_user_list(token):
    url = "https://slack.com/api/users.list"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    data = response.json()
    if data.get("ok"):
        return data["members"]
    else:
        print("Error retrieving user list.")
        return []


def list_channels(token):
    url = "https://slack.com/api/conversations.list"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    data = response.json()
    if data.get("ok"):
        if verbose:
            print("Response:", response.text)  
        return data["channels"]  
    else:
        print("Error retrieving conversations list.")
        return []

def check_user_membership(token, channel_id):
    url = f"https://slack.com/api/conversations.members?channel={channel_id}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    data = response.json()
    if response.status_code == 200 and data.get("ok"):
        return True
    return False




def check_permissions(token):
    # perms for files.list
    files_list_url = "https://slack.com/api/files.list?limit=1"
    files_list_headers = {"Authorization": f"Bearer {token}"}
    files_list_response = requests.get(files_list_url, headers=files_list_headers)
    files_list_data = files_list_response.json()
    files_list_permission = "files:read" if files_list_data.get("ok") else None

    # perms for users.list
    users_list_url = "https://slack.com/api/users.list?limit=1"
    users_list_headers = {"Authorization": f"Bearer {token}"}
    users_list_response = requests.get(users_list_url, headers=users_list_headers)
    users_list_data = users_list_response.json()
    users_list_permission = "users:read" if users_list_data.get("ok") else None

    # perms for conversations.list
    conversations_list_url = "https://slack.com/api/conversations.list?limit=1"
    conversations_list_headers = {"Authorization": f"Bearer {token}"}
    conversations_list_response = requests.get(conversations_list_url, headers=conversations_list_headers)
    conversations_list_data = conversations_list_response.json()
    conversations_list_permission = "conversations:read" if conversations_list_data.get("ok") else None


    dump_logs_permission = check_dump_logs_permission(token)


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


def main():
    parser = argparse.ArgumentParser(description="Download files from Slack channels")
    parser.add_argument("token", type=str, help="Slack API token")
    parser.add_argument("--list-file-urls", action='store_true', help="Get file URLs")
    parser.add_argument("--download-files", action='store_true', help="Download files")
    parser.add_argument("--output-directory", type=str, help="Output directory for downloaded files")

    parser.add_argument("--list-users", action='store_true', help="Get list of users")
    parser.add_argument("--list-channels", action='store_true', help="Get list of channels")
    parser.add_argument("--check-permissions", action='store_true', help="Check API token permissions")
    parser.add_argument("--list-files", action='store_true', help="List all files from all channels")
    parser.add_argument("--dump-logs", action='store_true', help="Dump team access logs")
    parser.add_argument("--verbose", "-v", action='store_true', help="Enable verbose logging for troubleshooting")

    args = parser.parse_args()
    token = args.token

    if args.list_files:
        all_file_urls = list_files(token, args.verbose)  # Pass the verbose flag
        print("List of All File URLs:")
        for file_url in all_file_urls:
            print(file_url)

    elif args.check_permissions:
        permissions = check_permissions(token)
        print("API Token Permissions:")
        for endpoint, permission in permissions['API Token Permissions'].items():
            print(f"{endpoint}: {permission}")

        print()
        print("Available Flags:")
        for flag in permissions['Available Flags']:
            print(flag)

    elif args.list_file_urls:
        channel_list = list_channels(token)
        for channel in channel_list:
            file_urls = list_file_urls(token, channel)
            print(f"File URLs for channel {channel}:")
            for file_url in file_urls:
                print(file_url)

    elif args.list_users:
        user_list = list_user_list(token)
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

    elif args.list_channels:
        channel_list = list_channels(token)
        user_membership = [] 
        

        for channel in channel_list:
            channel_id = channel['id']
            is_member = check_user_membership(token, channel_id)
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

    elif args.dump_logs:
        dump_logs(token, args.verbose)

    elif args.download_files:
        channel_list = list_channels(token)
        all_file_urls = []
        for channel in channel_list:
            file_urls = list_file_urls(token, channel)
            all_file_urls.extend(file_urls)
        download_files(token, all_file_urls, args.output_directory, args.verbose)



if __name__ == "__main__":
    main()
