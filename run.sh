#!/bin/bash

clear

rm database.db
# Open a new terminal window and run the first Python file
gnome-terminal -- python3 ServerGUI.py

# Open another new terminal window and run the second Python file
gnome-terminal -- python3 ClientGUI.py