# SlackAttack!

## Background

There are a plethora of post-ex Slack hacking tools for pillaging files, users, channels, and conversations. However, many of these tools don't support Slack's new API authentication model or are no longer supported and don't work out of the box. The goal with this tool is to pick up where the others left off so we can keep demonstrating risk of plaintext Slack bot tokens and achieve our objectives! 

## Description

SlackAttack! is a Python script designed to interact with Slack's API using a Slack token you may obtain during an engagement. It can perform various flavors of enumeration such as dumping channel information, downloading files, and enumerating users. It offers the following capabilities:

- **Get Channel List**: Retrieve a list of channels in your Slack workspace.
- **Get File URLs**: Obtain a list of file URLs within specific Slack channels.
- **Download Files**: Download files from Slack channels to your local machine.
- **Get User List**: Retrieve a list of users in your Slack workspace.

## Installation

To use the SlackAttack!, follow these installation steps:

1. Clone this repository to your local machine using Git:

   ```
   git clone https://github.com/fr4nk3nst1ner/slackattack.git
   ```

2. Change your working directory to the project folder:

   ```
   cd slackattack
   ```

3. Install the required Python packages using pip:

   ```
   pip3 install -r requirements.txt
   ```

## Usage

You can use the SlackAttack! with various command-line arguments to perform specific actions. Here's how to use each argument:

- **Token**: You need to provide your Slack API token as an argument for authentication. Replace `YOUR_TOKEN` with your actual token.

### Check the permissions and what you can do with your token 

Use the `--check-permissions` argument to list permissions and return commands you can run: 

```shell
python3 slackattack.py YOUR_TOKEN --check-permissions
```

### Get Channel List

Use the `--list-channels` argument to retrieve a list of channels in your Slack workspace:

```shell
python3 slackattack.py YOUR_TOKEN --list-channels
```

### Get File URLs

Use the `--list-file-urls` argument along with the `--channel` argument to retrieve file URLs for a specific channel:

```shell
python3 slackattack.py YOUR_TOKEN --list-file-urls --channel CHANNEL_ID
```

### Download Files

Use the `--download-files` argument to download files from Slack channels:

```shell
python3 slackattack.py YOUR_TOKEN --download-files
```

### Get User List

Use the `--list-users` argument to retrieve a list of users in your Slack workspace:

```shell
python3 slackattack.py YOUR_TOKEN --list-users
```

Replace `YOUR_TOKEN` and other placeholders with your actual Slack API token and channel ID when running the commands.

Feel free to contribute to this project or report any issues by creating a GitHub issue or pull request.

Happy Slack hacking!

## Shoutouts

Props to the author of [Slack Pirate](https://github.com/emtunc/SlackPirate). While it seems there may be other tools out there that sort of solved this problem, Slack Pirate was my main source of inspiration when creating this beyond just the one-off poc that solved my unique need. 

## To Do

- [x] Add functionality to return associated permissions for supplied token 
- [ ] Add functionality to identify secrets or sensitive data from files or conversations (e.g., regex)
- [ ] Add support and distinguish usability from bot and user tokens
- [ ] Add functionality to support cookie auth

