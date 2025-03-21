# X CLI

X CLI is a command-line tool written in Go that enables you to authenticate with Twitter using the OAuth2 PKCE flow and post tweets directly from your terminal. The tool automates obtaining an access token by launching a browser for authentication, capturing the callback, and then exchanging the code for an access token. It also supports a simple REPL (read–eval–print loop) for posting tweets interactively.

## Features

- **OAuth2 with PKCE**: Securely obtain an access token via Twitter's OAuth2 API.
- **Interactive CLI**: Post tweets directly from the terminal using an easy-to-use prompt.
- **Automatic Configuration**: On first run, the app prompts for your Twitter Client ID and saves it to `/etc/xcli/config`.
- **Linux-Only Browser Launch**: Uses `xdg-open` to open the default browser for authentication.
- **Installation Script**: Includes an `install.sh` script that compiles `xcli.go`, installs the binary to `/bin/x`, and sets up the configuration.

## Prerequisites

- **Go**: Ensure that https://golang.org/dl/ is installed on your system.
- **Sudo Access**: Required to write to system directories like `/etc/xcli` and `/bin`.

## Installation

1. **Clone or Download** this repository containing `xcli.go` and `install.sh`.

2. **Make the Install Script Executable**:
   chmod +x install.sh

3. **Run the Install Script with Sudo**:
   sudo ./install.sh

   The script will:
   - Check for sudo permissions.
   - Compile `xcli.go` into a binary named `x`.
   - Copy the binary to `/bin/x`.
   - Create the `/etc/xcli` directory and configuration file if it doesn't already exist.
   - Prompt you to enter your Twitter Client ID.
   - Remind you that your Twitter Developer Portal callback URL must be set to `http://localhost:5000/callback`.

## Configuration

The application expects a configuration file at `/etc/xcli/config` in JSON format. This file should contain your Twitter Client ID. For example:

{
  "client_id": "your_client_id_here"
}

If this file does not exist, the first run of the installation script will prompt you for your CLIENT ID and create the file automatically.

## Callback URL

Ensure that your Twitter Developer Portal is configured with the following callback URL:

http://localhost:5000/callback

This is necessary for the OAuth2 authentication flow to work correctly.

## Usage

After installation, you can run the application by simply executing:

x

When the application starts, it will:

1. Launch your default browser to authenticate with Twitter.
2. Capture the OAuth2 callback to retrieve the authorization code.
3. Exchange the authorization code for an access token.
4. Enter a command loop where you can type tweet text and press Enter to post it.
5. Type `exit` or `quit` to end the session.

## Troubleshooting

- **Permission Errors**: Make sure you run the installation script with sudo since writing to `/etc/xcli` and `/bin` requires elevated privileges.
- **Callback Issues**: Verify that your callback URL in the Twitter Developer Portal is set to `http://localhost:5000/callback`.

## License

This project is open source. Feel free to modify and enhance it according to your needs.

---

Enjoy using X CLI for your Twitter automation needs!
