#!/usr/bin/python3

import re
import sys
from collections import Counter
import ipaddress  # For validating and classifying IPs
from datetime import datetime # To handle timestamps
import time # To track time for progress updates
import traceback # Import traceback module

# --- Configuration ---
TOP_N = 15 # How many top items to show for each category
MAX_UNPARSED_TO_PRINT = 50 # Limit the number of unparsed lines printed
PROGRESS_UPDATE_INTERVAL = 1.0 # Print progress every 1 second

# --- Regular Expressions ---
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?\b')
MAC_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b') # Corrected non-capturing group
EMAIL_REGEX = re.compile(r'<([^>]+?@[^>]+?\.[a-zA-Z]{2,})>')
QUEUE_ID_REGEX = re.compile(r'\b([A-F0-9]{10,12}):\s')
MESSAGE_ID_REGEX = re.compile(r'message-id=<(.*?)>')
USERNAME_REGEX = re.compile(
    r'(?:sasl_username|uid|user)=(?:"?)([\w.-]+)(?:"?)|'
    r'pam\(([\w.-]+),'
)
HOSTNAME_REGEX = re.compile(r'\[([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\]|client_name=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|helo=<([^>]+?\.[^>]+?)>')
DROP_REGEX = re.compile(r'firewall: DROP (\S+)')
AUTH_FAIL_REGEX = re.compile(r'(?:Authentication failure|authentication failed)')
SASL_FAIL_REGEX = re.compile(r'SASL LOGIN authentication failed')
PAM_FAIL_REGEX = re.compile(r'pam_authenticate\(\) failed')
PSK_MISMATCH_REGEX = re.compile(r'AP-STA-POSSIBLE-PSK-MISMATCH')
STATUS_SENT_REGEX = re.compile(r'status=sent')
STATUS_BOUNCED_REGEX = re.compile(r'status=bounced')
PASSED_CLEAN_REGEX = re.compile(r'Passed CLEAN')
TIMESTAMP_REGEX = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\+\-]\d{2}:\d{2})\s')

# --- Switch Specific Regexes ---
SWITCH_INT_TRANSITION_REGEX = re.compile(r'note\s+([\w\/]+)\s+is\s+transitioned\s+from\s+the\s+(\w+)\s+state\s+to\s+the\s+(\w+)\s+state', re.IGNORECASE)
SWITCH_LINK_EVENT_REGEX = re.compile(r'%(LINK-W-Down|LINK-I-Up):\s+([\w\/]+)(?:#\d+)?', re.IGNORECASE)
SWITCH_LOGIN_REGEX = re.compile(r'system:\s+user\s+(\S+)\s+(logged\s+in|logged\s+out)\s+from\s+(\S+)', re.IGNORECASE)
SWITCH_LOGIN_FAILURE_REGEX = re.compile(r'system:\s+login\s+failure\s+for\s+user\s+(\S+)\s+from\s+(\S+)', re.IGNORECASE)
SWITCH_STP_CHANGE_REGEX = re.compile(r'Spanning Tree Topology Change', re.IGNORECASE)

# --- DHCP Specific Regex ---
DHCP_EVENT_REGEX = re.compile(r'(DHCPREQUEST|DHCPACK)', re.IGNORECASE)


# --- Data Structures ---
line_count = 0
error_lines = 0
warning_lines = 0
unparsed_line_count = 0
unparsed_lines_sample = []

first_timestamp = None
last_timestamp = None

ip_counter = Counter()
public_ip_counter = Counter()
private_ip_counter = Counter()
mac_counter = Counter() # General counter for all MACs found
email_sender_counter = Counter()
email_recipient_counter = Counter()
queue_id_counter = Counter()
message_id_counter = Counter()
username_counter = Counter()
hostname_counter = Counter()
source_host_counter = Counter()
service_counter = Counter()
firewall_drop_reasons = Counter()
auth_failures = Counter()
failed_sasl_users = Counter()
failed_pam_users = Counter()
psk_mismatch_macs = Counter()
dhcp_mac_events = Counter() # Track MACs involved in DHCP events
status_sent_count = 0 # Initialized Globally
status_bounced_count = 0 # Initialized Globally
passed_clean_count = 0 # Initialized Globally

# Switch specific counters
processed_switch_hosts = set()
switch_interface_transitions = Counter()
switch_link_events = Counter()
switch_logins_success = Counter()
switch_logins_failed = Counter()
switch_logouts = Counter()
switch_stp_changes = Counter()


# --- Variables for Progress Update ---
last_progress_update_time = time.time()
start_time = last_progress_update_time

# --- Helper Functions ---
def is_public_ip(ip_str):
    """Checks if an IP address string is likely public."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_loopback and not ip.is_multicast
    except ValueError:
        return False

def is_private_ip(ip_str):
    """Checks if an IP address string is likely private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def print_top_n(title, counter, n=TOP_N):
    """Helper function to print formatted top N items from a Counter."""
    print(f"\n--- {title} (Top {n}) ---")
    if not counter:
        print("  (No data)")
        return
    total = sum(counter.values())
    print(f"  Total unique: {len(counter)}, Total mentions: {total}")
    for item, count in counter.most_common(n):
        percentage = (count / total) * 100 if total else 0
        if isinstance(item, tuple):
            item_str = " - ".join(map(str, item))
        else:
            item_str = str(item)
        print(f"  {item_str}: {count} ({percentage:.1f}%)")

# --- Main Processing Logic ---
try:
    for line in sys.stdin:
        line_count += 1
        line_lower = line.lower()

        # --- Progress Update ---
        current_time = time.time()
        if current_time - last_progress_update_time >= PROGRESS_UPDATE_INTERVAL:
            elapsed_time = current_time - start_time
            lines_per_sec = line_count / elapsed_time if elapsed_time > 0 else 0
            print(f"\rProcessed {line_count} lines ({lines_per_sec:.0f} lines/sec)...", end='', file=sys.stderr, flush=True)
            last_progress_update_time = current_time

        # --- Extract and Update Timestamps ---
        timestamp_match = TIMESTAMP_REGEX.match(line)
        current_timestamp = None
        if timestamp_match:
            current_timestamp = timestamp_match.group(1)
            if first_timestamp is None:
                first_timestamp = current_timestamp
            last_timestamp = current_timestamp
            line_content = line[timestamp_match.end():]
        else:
            line_content = line

        # --- Basic Error/Warning Count ---
        if "error" in line_lower:
            error_lines += 1
        if "warning" in line_lower:
            warning_lines += 1

        # --- Attempt Basic Log Structure Parsing ---
        parts = line_content.split(maxsplit=2)
        is_switch_line = False
        if len(parts) >= 2:
            source_host = parts[0]
            service_part = parts[1].split('[')[0].rstrip(':')
            source_host_counter[source_host] += 1
            service_counter[service_part] += 1
            message = parts[2] if len(parts) > 2 else ""

            if source_host.startswith("sw-"):
                 is_switch_line = True
                 processed_switch_hosts.add(source_host)

            # --- General Identifier Extraction ---
            ips_found = set()
            for ip in IP_REGEX.findall(line):
                 try:
                     ip_obj = ipaddress.ip_address(ip.split('/')[0])
                     if ip not in ips_found:
                         ip_counter[ip] += 1
                         ips_found.add(ip)
                         if is_public_ip(ip.split('/')[0]):
                             public_ip_counter[ip] += 1
                         elif is_private_ip(ip.split('/')[0]):
                             private_ip_counter[ip] +=1
                 except ValueError:
                     continue
            macs_in_line = MAC_REGEX.findall(line_lower)
            for mac in macs_in_line:
                 mac_counter[mac] += 1
            if service_part == 'dhcpd' and DHCP_EVENT_REGEX.search(message):
                for mac in macs_in_line:
                    dhcp_mac_events[mac] += 1
            sender_match = re.search(r'sender=<?([^ >]+@[^ >]+)>?', line)
            if sender_match:
                email_sender_counter[sender_match.group(1)] +=1
            recipient_match = re.search(r'recipient=<?([^ >]+@[^ >]+)>?', line)
            if recipient_match:
                 email_recipient_counter[recipient_match.group(1)] += 1
            for qid_match in QUEUE_ID_REGEX.findall(line):
                queue_id_counter[qid_match] += 1
            q_match = re.search(r'queued as ([A-F0-9]+)', line)
            if q_match:
                 queue_id_counter[q_match.group(1)] += 1
            for msgid in MESSAGE_ID_REGEX.findall(line):
                 message_id_counter[msgid] += 1
            found_user = False
            for match in USERNAME_REGEX.finditer(line):
                user = match.group(1) or match.group(2)
                if user and user.lower() not in ['unknown', 'undefined', '(null)', '']:
                    username_counter[user] += 1
                    found_user = True
                    if SASL_FAIL_REGEX.search(line):
                        failed_sasl_users[user] += 1
                    if PAM_FAIL_REGEX.search(line):
                         failed_pam_users[user] += 1
            if not found_user and AUTH_FAIL_REGEX.search(line):
                 auth_failures['Unknown User/Format'] += 1
            for match in HOSTNAME_REGEX.finditer(line):
                hostname = match.group(1) or match.group(2) or match.group(3)
                if hostname and hostname.lower() not in ['localhost', 'unknown', '']:
                    hostname_counter[hostname.lower()] += 1

            # --- Specific Actions/Keywords (General) ---
            drop_match = DROP_REGEX.search(line)
            if drop_match:
                firewall_drop_reasons[f"DROP {drop_match.group(1)}"] += 1
            if AUTH_FAIL_REGEX.search(line):
                 auth_failures['Total Auth Failures'] += 1
                 if SASL_FAIL_REGEX.search(line):
                     auth_failures['SASL Fail'] += 1
                 if PAM_FAIL_REGEX.search(line):
                      auth_failures['PAM Fail'] += 1
            psk_match = PSK_MISMATCH_REGEX.search(line)
            if psk_match:
                auth_failures['PSK Mismatch'] += 1
                mac_in_line = MAC_REGEX.search(line_lower)
                if mac_in_line:
                    full_macs = MAC_REGEX.findall(line_lower)
                    if full_macs:
                       psk_mismatch_macs[full_macs[0]] += 1
            if STATUS_SENT_REGEX.search(line):
                 status_sent_count += 1 # Incrementing here
            if STATUS_BOUNCED_REGEX.search(line):
                 status_bounced_count += 1 # Incrementing here
            if PASSED_CLEAN_REGEX.search(line):
                 passed_clean_count += 1 # Incrementing here

            # --- Switch Specific Analysis ---
            if is_switch_line:
                transition_match = SWITCH_INT_TRANSITION_REGEX.search(message)
                if transition_match:
                    interface = transition_match.group(1)
                    from_state = transition_match.group(2)
                    to_state = transition_match.group(3)
                    switch_interface_transitions[(source_host, interface, from_state, to_state)] += 1
                link_match = SWITCH_LINK_EVENT_REGEX.search(line_content)
                if link_match:
                    event_type = "UP" if "up" in link_match.group(1).lower() else "DOWN"
                    interface = link_match.group(2)
                    switch_link_events[(source_host, interface, event_type)] += 1
                if service_part == 'system':
                    login_match = SWITCH_LOGIN_REGEX.search(message)
                    if login_match:
                        user = login_match.group(1)
                        status = login_match.group(2).strip()
                        source_ip = login_match.group(3)
                        if "logged in" in status:
                            switch_logins_success[(source_host, user, source_ip)] += 1
                        elif "logged out" in status:
                            switch_logouts[(source_host, user, source_ip)] += 1
                    else:
                        fail_match = SWITCH_LOGIN_FAILURE_REGEX.search(message)
                        if fail_match:
                             user = fail_match.group(1)
                             source_ip = fail_match.group(2)
                             switch_logins_failed[(source_host, user, source_ip)] += 1
                if SWITCH_STP_CHANGE_REGEX.search(message):
                    switch_stp_changes[source_host] += 1
        else:
            # --- Line didn't fit the basic structure ---
            unparsed_line_count += 1
            if len(unparsed_lines_sample) < MAX_UNPARSED_TO_PRINT:
                unparsed_lines_sample.append(line.strip())
            continue

except Exception as e:
    print(f"\nAn error occurred during processing: {e}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr) # Print detailed traceback to stderr
    sys.exit(1)
finally:
    print("\r" + " " * 50 + "\r", end='', file=sys.stderr, flush=True)

# --- Print Summary Statistics ---
print("=" * 30)
print("Log File Analysis Summary")
print("=" * 30)
print(f"Processed {line_count} lines.")
if first_timestamp and last_timestamp:
    print(f"Time Range: {first_timestamp} -> {last_timestamp}")
else:
    print("Time Range: Could not determine from log lines.")
elapsed_total = time.time() - start_time
print(f"Total processing time: {elapsed_total:.2f} seconds")
print(f"Found {warning_lines} WARNING lines.")
print(f"Found {error_lines} ERROR lines.")
print(f"Found {unparsed_line_count} lines that did not match basic structure.")

print("\n--- General Counts ---")
print(f"  Postfix Status Sent: {status_sent_count}")
print(f"  Postfix Status Bounced: {status_bounced_count}")
print(f"  Amavis Passed CLEAN: {passed_clean_count}")

print_top_n("Source Hosts (Log Origin)", source_host_counter)
print_top_n("Services / Processes", service_counter)
print_top_n("Detected Hostnames/Domains", hostname_counter)
print_top_n("Detected MAC Addresses (All)", mac_counter)
print_top_n("MAC Addresses in DHCP Events", dhcp_mac_events)
print_top_n("Detected Email Senders", email_sender_counter)
print_top_n("Detected Email Recipients", email_recipient_counter)
print_top_n("Detected Postfix Queue IDs", queue_id_counter, n=5)
print_top_n("Detected Message IDs", message_id_counter, n=5)

print("\n" + "=" * 30)
print("IP Address Statistics")
print("=" * 30)
print_top_n("All Detected IPs", ip_counter)
print_top_n("Likely Public IPs", public_ip_counter)
print_top_n("Likely Private/Loopback IPs", private_ip_counter)

print("\n" + "=" * 30)
print("Security Relevant Events")
print("=" * 30)
print("\n--- Firewall Drops ---")
print_top_n("Firewall DROP Reasons", firewall_drop_reasons)
print("\n--- Authentication Failures (All Sources) ---")
print(f"  Total Authentication Failures (Detected): {auth_failures.get('Total Auth Failures', 0)}")
print(f"    SASL Failures: {auth_failures.get('SASL Fail', 0)}")
print(f"    PAM Failures: {auth_failures.get('PAM Fail', 0)}")
print(f"    WiFi PSK Mismatches: {auth_failures.get('PSK Mismatch', 0)}")
print(f"    Unknown Format/User Failures: {auth_failures.get('Unknown User/Format', 0)}")
print_top_n("Usernames Mentioned in Logs (All Contexts, Filtered)", username_counter)
print_top_n("Usernames in SASL Login Failures", failed_sasl_users)
print_top_n("Usernames in PAM Auth Failures", failed_pam_users)
print_top_n("MAC Addresses with WiFi PSK Mismatches", psk_mismatch_macs)

# --- Print Switch Specific Statistics ---
print("\n" + "=" * 30)
print(f"Switch Specific Statistics ({len(processed_switch_hosts)} unique switches found starting with 'sw-')")
print("=" * 30)
print_top_n("Switch Interface Transitions (Host, Interface, From, To)", switch_interface_transitions)
print_top_n("Switch Link Events (Host, Interface, State)", switch_link_events)
print_top_n("Successful Switch Logins (Host, User, Source IP)", switch_logins_success)
print_top_n("Failed Switch Logins (Host, User, Source IP)", switch_logins_failed)
print_top_n("Switch Logouts (Host, User, Source IP)", switch_logouts)
print_top_n("Switch STP Topology Changes (Host)", switch_stp_changes)

# --- Print Unparsed Lines Sample ---
if unparsed_lines_sample:
    print("\n" + "=" * 30)
    print(f"Sample of Unparsed Lines (First {min(len(unparsed_lines_sample), MAX_UNPARSED_TO_PRINT)})")
    print("=" * 30)
    for line in unparsed_lines_sample:
        print(f"  {line}")
    if unparsed_line_count > MAX_UNPARSED_TO_PRINT:
        print(f"  (... and {unparsed_line_count - MAX_UNPARSED_TO_PRINT} more unparsed lines)")

print("\n" + "=" * 30)
print("Analysis Complete.")
print("=" * 30)
