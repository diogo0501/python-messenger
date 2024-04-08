#!/bin/bash

clear

gnome-terminal -- rm database.db

gnome-terminal -- python3 ServerGUI.py

# Function to wait for the "r" key press
wait_for_enter_key() {
    local key
    

    if [ "$1" == "close" ]; then
        echo "Press 'Enter' key to close..."
        while true; do
            read -rsn1 key
            if [ "$key" = "" ]; then
                killall gnome-terminal
                break
            fi
        done
    else
        echo "Press 'Enter' key to continue..."
        while true; do
            read -rsn1 key
            if [ "$key" = "" ]; then
                break
            fi
        done
    fi
}

# Call the function to wait for the "r" key
wait_for_enter_key ""

# SQL Injection command
gnome-terminal -- python3 testClient.py --server-ip 0 --server-port 9000 --username ola --password pass --connection-type sign

gnome-terminal -- python3 ClientGUI.py
# SQL Injection command
# gnome-terminal -- python3 testClient.py --server-ip 0 --server-port 9000 --username hey --password "pass'); DROP TABLE users; --" --connection-type sign
# Command Injection eg : hi'), self.create_chat_window(), print('hi
wait_for_enter_key "close"
$SHELL