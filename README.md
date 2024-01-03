
# SlackAttack!

## Background

SlackAttack! is a Python script designed to interact with Slack's API using a Slack token or cookie that you may obtain during an engagement. It supports Slack's new API authentication model, allowing you to demonstrate the risks associated with plaintext Slack bot tokens and achieve your objectives!

## Description

SlackAttack! can perform various enumeration tasks, such as dumping channel information, downloading files, and enumerating users. It offers the following capabilities:

- **Get Channel List**: Retrieve a list of channels in your Slack workspace.
- **Get File URLs**: Obtain a list of file URLs within specific Slack channels.
- **Download Files**: Download files from Slack channels to your local machine.
- **Get User List**: Retrieve a list of users in your Slack workspace.

## Installation

To use SlackAttack!, follow these installation steps:

1. Clone this repository to your local machine using Git:
  
```  
shell
git clone https://github.com/fr4nk3nst1ner/slackattack.git
```
    
2. Change your working directory to the project folder:
  
```  
shell
cd slackattack
```
    
3. Install the required Python packages using pip:
  
```  
shell
pip3 install -r requirements.txt
```
    

## Usage

You can use SlackAttack! with various command-line arguments to perform specific actions. Here's how to use each argument:

- **Token**: You need to provide your Slack API token as an argument for authentication. Replace `YOUR_TOKEN` with your actual token.
    
- **Cookie**: You can alternatively use a "xoxd-*" cookie for authentication. It will automate the processes involved to retrieve the "xoxc-*" session cookie to interact with the API. Replace `YOUR_COOKIE` with your actual cookie.
    

### Check the permissions and what you can do with your token or cookie

Use the `--check-permissions` argument to list permissions and return commands you can run:

```
shell
python3 slackattack.py --token YOUR_TOKEN --check-permissions`
```

or

```
shell
python3 slackattack.py --cookie 'YOUR_COOKIE' --check-permissions`
```

### Get Channel List

Retrieve a list of channels in your Slack workspace:

```
shell
python3 slackattack.py --token YOUR_TOKEN --list-channels`
```

or

```
shell
python3 slackattack.py --cookie 'YOUR_COOKIE' --list-channels`
```

### Get File URLs

Retrieve file URLs for a specific channel using the `--channel` argument:

```
shell
python3 slackattack.py --token YOUR_TOKEN --list-file-urls --channel CHANNEL_ID`
```

or

```
shell
python3 slackattack.py --cookie 'YOUR_COOKIE' --list-file-urls --channel CHANNEL_ID`
```

### Download Files

Download files from Slack channels:

```
shell
python3 slackattack.py --token YOUR_TOKEN --download-files`
```

or

```
shell
python3 slackattack.py --cookie 'YOUR_COOKIE' --download-files`
```

### Get User List

Retrieve a list of users in your Slack workspace:

```
shell
python3 slackattack.py --token YOUR_TOKEN --list-users`
```

or

```
shell
python3 slackattack.py --cookie 'YOUR_COOKIE' --list-users`
```

Replace `YOUR_TOKEN`, `YOUR_COOKIE`, and other placeholders with your actual Slack API token, cookie, and channel ID when running the commands.

Feel free to contribute to this project or report any issues by creating a GitHub issue or pull request.

Happy Slack hacking!

## Shoutouts

Props to the author of [Slack Pirate](https://github.com/emtunc/SlackPirate). While there may be other tools out there that have solved this problem, Slack Pirate was my main source of inspiration when creating this tool beyond just the one-off proof of concept that solved my unique need.

## To Do

- [x]  Add functionality to return associated permissions for supplied token or cookie.
- [ ]  Add functionality to identify secrets or sensitive data from files or conversations (e.g., regex).
- [ ]  Add support and distinguish usability from bot and user tokens.
- [x]  Add functionality to support cookie auth.
