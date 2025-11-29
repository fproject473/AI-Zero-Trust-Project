import pandas as pd
import re
from datetime import datetime
from collections import defaultdict

def parse_auth_log(log_file_path='/var/log/auth.log'): 
    """
    Parse Linux auth.log file for security events
    """
    events = []

    # Regex patterns for common auth.log events
    patterns = {
        'failed_password': r'Failed password for (\S+) from (\S+) port (\d+)',
        'accepted_password': r'Accepted password for (\S+) from (\S+) port (\d+)',
        'invalid_user': r'Invalid user (\S+) from (\S+)',
        'sudo_command': r'sudo:\s+(\S+).*COMMAND=(.+)',
        'new_session': r'pam_unix\(.*\): session opened for user (\S+)',
        'session_closed': r'pam_unix\(.*\): session closed for user (\S+)',
        'authentication_failure': r'authentication failure.*user=(\S+)',
    }

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                event = {}

                # Extract timestamp (assuming standard syslog format)
                timestamp_match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                if timestamp_match:
                    event['Timestamp'] = timestamp_match.group(1)

                # Check each pattern
                for event_type, pattern in patterns.items():
                    match = re.search(pattern, line)
                    if match:
                        event['EventType'] = event_type

                        if event_type == 'failed_password':
                            event['User'] = match.group(1)
                            event['SourceIP'] = match.group(2)
                            event['Port'] = match.group(3)

                        elif event_type == 'accepted_password':
                            event['User'] = match.group(1)
                            event['SourceIP'] = match.group(2)
                            event['Port'] = match.group(3)

                        elif event_type == 'invalid_user':
              
