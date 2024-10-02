#!/bin/bash

# Installation script for "harden" command

# Ensure main.sh is executable
chmod +x KaliHarden/main.sh

# Move the script to /usr/local/bin as "harden"
sudo cp KaliHarden/main.sh /usr/local/bin/harden

# Ensure it's executable in the new location
sudo chmod +x /usr/local/bin/harden

# Inform the user that the installation is complete
echo "Installation complete! You can now use the 'harden' command."
