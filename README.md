# Summary
fglogger - A Syslog server for Fortigate firewalls

This script receives syslog messages from a FortiGate device and send them to a SQLite database. The script assumes FortiOS 5.4 but it is generic and self-contained. 

# Installation
Download the fglogger.py file to your local machine then run the script from the command line.
Configure the Fortigate to send syslog messages to the IP address or your local machine.

## Dependencies
* sqlite3
* pyparsing

# Documentation
See the comments in the script.

# License
MIT License. See the header of fglogger.py

# History
Any future chnages will be in the CHANGES file.
