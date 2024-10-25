import paramiko # type: ignore
import re
import csv
import time
import os
from dotenv import load_dotenv # type: ignore

# Function to execute commands on FortiWeb device
def execute_commands(shell, commands):
    results = []
    for command in commands:
        shell.send(command + '\n')
        time.sleep(1)
        output = shell.recv(65535).decode('utf-8')
        results.append((command, output))
    return results

# Function to connect to the FortiWeb device
def connect_to_fortiweb(hostname, username, password, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print("Attempting to connect to FortiWeb device...")
        client.connect(hostname, port=port, username=username, password=password)
        print("SSH connection successful.")
        shell = client.invoke_shell()
        time.sleep(2)  # Allow time for login
        return shell
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return None
    except Exception as e:
        print(f"Connection error: {e}")
        return None

# Check if default admin account is removed and super admin is configured
def check_default_admin_removed(shell):
    print("Checking for default 'admin' account...")
    admin_command = 'get system admin'
    output = execute_commands(shell, [admin_command])[0][1]
    
    # Check if 'admin' is present in the output
    if 'admin' in output:
        print("Default 'admin' account found.")
        return "Non-Compliant"
    
    print("Default 'admin' account is not found.")
    return "Compliant"

def check_rbac_profiles(shell):
    print("Manual check needed to limit full administrative rights by creating profiles (RBAC).")
    return "Manual check needed"

def check_password_policy(shell):
    print("Checking password policy settings...")
    password_policy_command = 'get system password-policy'
    output = execute_commands(shell, [password_policy_command])[0][1]

    required_settings = {
        'min-length': 8,
        'min-upper-case-letter': 1,
        'min-lower-case-letter': 1,
        'min-number': 1,
        'min-non-alphanumeric': 1,
    }

    for key, min_value in required_settings.items():
        pattern = fr"{key}\s*:\s*(\d+)"
        match = re.search(pattern, output)
        if not match:
            print(f"Password policy setting missing: {key} is not found.")
            return "Non-Compliant"
        
        actual_value = int(match.group(1))
        
        # Check for min-length condition separately
        if key == 'min-length' and actual_value < min_value:
            print(f"Password policy setting mismatch: {key} should be at least {min_value} but found {actual_value}.")
            return "Non-Compliant"
        
        # Check for other settings to ensure they are not lower than the minimum required values
        if key != 'min-length' and actual_value < min_value:
            print(f"Password policy setting mismatch: {key} should be at least {min_value} but found {actual_value}.")
            return "Non-Compliant"

    print("Strong password rules are enabled.")
    return "Compliant"

def check_trusted_hosts(shell):
    print("Checking trusted hosts settings...")
    admin_command = 'get system admin'
    output = execute_commands(shell, [admin_command])[0][1]
    
    # Check for 'trusthostv4' line
    if 'trusthostv4:' in output:
        # Extract the trusted host value
        pattern = r'trusthostv4:\s*(.+)'
        match = re.search(pattern, output)
        if match:
            trusted_host = match.group(1).strip()
            # Check if the trusted host is not blank or set to a wildcard
            if trusted_host and trusted_host != '::/0':
                print(f"Trusted host found: {trusted_host}.")
                return "Compliant"
    
    print("No valid trusted hosts configuration found.")
    return "Non-Compliant"

def check_admin_timeout(shell):
    print("Checking admin timeout settings...")
    timeout_command = 'get system global | grep -i admintimeout'
    output = execute_commands(shell, [timeout_command])[0][1]
    
    # Check for 'admintimeout' value
    pattern = r'admintimeout\s*:\s*(\d+)'
    match = re.search(pattern, output)
    
    if match:
        timeout_value = int(match.group(1).strip())
        if timeout_value != 5:
            print(f"Admin timeout is set to {timeout_value}. This is non-compliant.")
            return "Non-Compliant"
    
    print("Admin timeout is set to 5. This is compliant.")
    return "Compliant"

def check_remote_login_security_port1(shell):
    print("Checking remote login security settings for port1...")
    interface_command = 'get system interface'
    output = execute_commands(shell, [interface_command])[0][1]
    
    # Split the output by lines
    lines = output.splitlines()
    
    # Track if we're inside the port1 block
    in_port1 = False
    
    for line in lines:
        if '== [ port1 ]' in line:
            in_port1 = True
        elif '==' in line and in_port1:
            # We've reached another port, so exit the port1 block
            in_port1 = False
        
        # If we're inside the port1 block, check for allowaccess settings
        if in_port1 and 'allowaccess:' in line:
            allowaccess_value = line.split(':')[1].strip()
            # Allowed values for port1
            allowed_values = ["ssh", "https", "ping"]
            if allowaccess_value:
                access_list = allowaccess_value.split()
                if not all(access in allowed_values for access in access_list):
                    print(f"Allowaccess for port1 is set to '{allowaccess_value}'. This is non-compliant.")
                    return "Non-Compliant"
            else:
                print("Allowaccess for port1 is blank. This is compliant.")
                return "Compliant"
    
    print("Remote login security for port1 is configured correctly. This is compliant.")
    return "Compliant"

def check_remote_access_limited(shell):
    print("Checking remote access settings for all ports...")
    interface_command = 'get system interface'
    output = execute_commands(shell, [interface_command])[0][1]
    
    # Split the output by lines
    lines = output.splitlines()
    
    # Track the current port being processed
    current_port = None
    allowaccess_found = False
    
    for line in lines:
        # Identify port blocks (assuming they start with '== [ portX ]')
        if '==' in line:
            current_port = line.strip()
            allowaccess_found = False
        
        # Check allowaccess settings for each port
        if 'allowaccess:' in line:
            allowaccess_value = line.split(':')[1].strip()
            allowaccess_found = True

            if 'port1' in current_port:
                # For port1, ensure only ssh, https, and optionally ping are allowed
                allowed_values = ["ssh", "https", "ping"]
                if allowaccess_value:
                    access_list = allowaccess_value.split()
                    if not all(access in allowed_values for access in access_list):
                        print(f"{current_port} - Allowaccess is set to '{allowaccess_value}'. This is non-compliant for port1.")
                        return "Non-Compliant"
                else:
                    print(f"{current_port} - Allowaccess is blank. This is compliant for port1.")
            else:
                # For other ports, ensure only ping is allowed
                if allowaccess_value and allowaccess_value != "ping":
                    print(f"{current_port} - Allowaccess is set to '{allowaccess_value}'. This is non-compliant for non-port1 interfaces.")
                    return "Non-Compliant"
                elif not allowaccess_value:
                    print(f"{current_port} - Allowaccess is blank. This is compliant for non-port1 interfaces.")
    
    if not allowaccess_found:
        print("No allowaccess settings found. Default compliance assumed.")
    
    print("Remote access is limited to a single management interface. This is compliant.")
    return "Compliant"

def check_trusted_hosts_subnet(shell):
    print("Checking trusted host subnet mask...")
    trusthost_command = 'get system admin | grep -i trusthostv4'
    output = execute_commands(shell, [trusthost_command])[0][1]
    trusthost_entries = re.findall(r'trusthostv4:\s*[\d\.]+/\d+', output)

    for entry in trusthost_entries:
        if not entry.endswith('/32'):
            print(f"Non-compliant trusted host entry found: {entry}")
            return "Non-Compliant"
    
    print("All trusted hosts have a 32-bit subnet mask. This is compliant.")
    return "Compliant"

def check_admin_lockout_settings(shell):
    print("Checking administrator lockout settings...")
    lockout_command = 'get system global | grep -i admin-lockout'
    output = execute_commands(shell, [lockout_command])[0][1]
    min_threshold = 3
    min_duration = 300
    threshold_match = re.search(r'admin-lockout-threshold:\s*(\d+)', output)
    duration_match = re.search(r'admin-lockout-duration:\s*(\d+)', output)
    
    if threshold_match and duration_match:
        threshold_value = int(threshold_match.group(1))
        duration_value = int(duration_match.group(1))
        if threshold_value >= min_threshold and duration_value >= min_duration:
            print("Admin lockout settings are compliant.")
            return "Compliant"
        else:
            print("Admin lockout settings are below the required threshold or duration.")
            return "Non-Compliant"
    else:
        print("Required admin lockout settings not found.")
        return "Non-Compliant"
    
def check_pre_login_banner(shell):
    print("Checking if pre-login banner is enabled...")
    banner_command = 'get system global | grep -i banner'
    output = execute_commands(shell, [banner_command])[0][1]
    if re.search(r'pre-login-banner\s*:\s*enable', output, re.IGNORECASE):
        print("Pre-login banner is enabled.")
        return "Compliant"
    else:
        print("Pre-login banner is not enabled.")
        return "Non-Compliant"

def check_maintainer_account(shell):
    print("Manual check needed to ensure that the Maintainer account is disabled.")
    return "Manual check needed"

def check_logging_configuration(shell):
    print("Checking logging configuration...")
    event_log_command = 'get log event-log'
    event_log_output = execute_commands(shell, [event_log_command])[0][1]
    event_log_compliant = re.search(r'status\s*:\s*enable', event_log_output)
    syslogd_command = 'get log syslogd'
    syslogd_output = execute_commands(shell, [syslogd_command])[0][1]
    syslogd_compliant = (
        re.search(r'status\s*:\s*enable', syslogd_output) and 
        re.search(r'severity\s*:\s*warning', syslogd_output)
    )

    if event_log_compliant and syslogd_compliant:
        print("Auditing and logging configuration is compliant.")
        return "Compliant"
    else:
        print("Auditing and logging configuration is non-compliant.")
        return "Non-Compliant"

def check_ntp_synchronization(shell):
    print("Manual check needed to ensure system time is synchronizing with NTP Server.")
    return "Manual check needed"

def check_password_ageing(shell):
    print("Checking password expiry settings...")
    password_policy_command = 'get system password-policy'
    output = execute_commands(shell, [password_policy_command])[0][1]
    pattern = r"expire-day\s*:\s*(\d+)"
    match = re.search(pattern, output)
    
    if match:
        expire_day = int(match.group(1))
        if expire_day > 90:
            print("Password expiry is greater than 90 days.")
            return "Non-Compliant"
        print("Password expiry settings are compliant.")
        return "Compliant"
    
    print("Expire day setting not found.")
    return "Non-Compliant"

def check_logging_configuration(shell):
    print("Checking logging configurations...")

    # Check attack-log status
    attack_log_command = 'get log attack-log | grep -i status'
    attack_log_output = execute_commands(shell, [attack_log_command])[0][1]

    # Check event-log status
    event_log_command = 'get log event-log | grep -i status'
    event_log_output = execute_commands(shell, [event_log_command])[0][1]

    # Define compliant status variable
    compliant = True

    # Check attack-log status
    if not re.search(r'status\s*:\s*enable', attack_log_output):
        print("Attack log is not enabled.")
        compliant = False

    # Check event-log status
    if not re.search(r'status\s*:\s*enable', event_log_output):
        print("Event log is not enabled.")
        compliant = False

    if compliant:
        print("Logging configurations are compliant.")
        return "Compliant"
    else:
        return "Non-Compliant"
    
def check_syslog_server_configuration(shell):
    print("Manual check needed to ensure syslog server is configured on FortiWeb.")
    return "Manual check needed"

def check_alert_email_configuration(shell):
    print("Checking email policy configuration...")
    email_command = 'show log email-policy'
    output = execute_commands(shell, [email_command])[0][1]
    
    mailfrom_exists = 'mailfrom' in output
    mailto_exists = 'mailto' in output

    if mailfrom_exists and mailto_exists:
        print("Both 'mailfrom' and 'mailto' settings are configured.")
        return "Compliant"
    else:
        print("Missing 'mailfrom' or 'mailto' settings.")
        return "Non-Compliant"

def check_email_alert_severity(shell):
    print("Checking email policy severity configuration...")
    email_command = 'show log email-policy | grep -i severity'
    output = execute_commands(shell, [email_command])[0][1]
    
    if 'set severity alert' in output:
        print("Email alert severity is set to 'alert'.")
        return "Compliant"
    
    print("Email alert severity is not set to 'alert'.")
    return "Non-Compliant"

def check_html_input_sanitization(shell):
    print("Manual check needed to ensure that HTML application inputs are properly sanitized.")
    return "Manual check needed"

def check_http_methods(shell):
    print("Manual check needed to ensure that only specific HTTP methods (GET and POST) are allowed.")
    return "Manual check needed"

def check_https_redirection(shell):
    print("Manual check needed to ensure clients are redirected to HTTPS connections forcefully.")
    return "Manual check needed"

def check_waf_protection(shell):
    print("Manual check needed to ensure that WAF is protecting against known attacks and data leaks.")
    return "Manual check needed"

def check_cookie_protection(shell):
    print("Manual check needed to ensure that protection for cookie poisoning is enabled.")
    return "Manual check needed"

def check_false_positives(shell):
    print("Manual check needed to ensure that measures to reduce false positives are implemented.")
    return "Manual check needed"

def check_sql_injection_mitigation(shell):
    print("Manual check needed to ensure that false positive mitigation for SQL Injection signatures is enabled.")
    return "Manual check needed"

def check_dos_protection(shell):
    print("Manual check needed to ensure that protection from DoS attacks is enabled.")
    return "Manual check needed"

def check_ip_reputation(shell):
    print("Manual check needed to ensure that IP reputation for blacklisting/whitelisting clients is enabled.")
    return "Manual check needed"

def check_http_https_constraints(shell):
    print("Manual check needed to ensure that HTTP/HTTPS protocol constraints are enabled.")
    return "Manual check needed"

def check_machine_learning_enabled(shell):
    print("Manual check needed to ensure that Machine Learning is enabled (Optional).")
    return "Manual check needed"

def check_unused_interfaces(shell):
    print("Manual check needed to ensure that unused interfaces are disabled.")
    return "Manual check needed"

def check_os_firmware_update(shell):
    print("Manual check needed to ensure that OS and firmware are updated.")
    return "Manual check needed"

def check_automatic_signature_updates(shell):
    print("Manual check needed to ensure that automatic signature updates are enabled.")
    return "Manual check needed"

def check_restrict_local_policies(shell):
    print("Manual check needed to ensure that local policies are restricted.")
    return "Manual check needed"

def check_access_list_explicit_deny(shell):
    print("Manual check needed to ensure each access-list has an explicit deny statement.")
    return "Manual check needed"

def check_domain_name():
    print("Manual check needed: Verify that the domain name is set for the firewall.")
    return "Manual check needed"

def check_hostname_set(shell):
    print("Checking if hostname is configured...")
    command = 'get system global | grep -i hostname'
    output = execute_commands(shell, [command])[0][1]

    match = re.search(r"hostname\s*:\s*(\S+)", output)
    if match:
        print("Hostname is set:", match.group(1))
        return "Compliant"
    else:
        print("Hostname is not set.")
        return "Non-Compliant"




























####################################################################################################
def write_to_csv(compliance_results):
    with open('compliance_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Sr No.", "Control Objective", "Compliance Status"])
        for index, result in enumerate(compliance_results, start=1):
            writer.writerow([index, result['control_objective'], result['compliance_status']])

# Load credentials from .env file
load_dotenv()

hostname = os.getenv('HOSTNAME')
username = os.getenv('USERNAME')
password = os.getenv('PASSWORD')
ssh_port = os.getenv('PORT')

shell = connect_to_fortiweb(hostname, username, password, port=ssh_port)

if shell:
    compliance_results = []
############################################################################################################

    admin_compliance = check_default_admin_removed(shell)
    compliance_results.append({
        "control_objective": "Ensure Default admin account is removed and New Super admin account has been configured",
        "compliance_status": admin_compliance
    })

    rbac_compliance = check_rbac_profiles(shell)
    compliance_results.append({
        "control_objective": "Limit full administrative rights by creating profiles (RBAC)",
        "compliance_status": rbac_compliance
    })

    password_policy_compliance = check_password_policy(shell)
    compliance_results.append({
        "control_objective": "Ensure Strong password rules are enabled",
        "compliance_status": password_policy_compliance
    })

    trusted_hosts_compliance = check_trusted_hosts(shell)
    compliance_results.append({
        "control_objective": "Ensure no other user except Trusted host can access the firewall",
        "compliance_status": trusted_hosts_compliance
    })

    admin_timeout_compliance = check_admin_timeout(shell)
    compliance_results.append({
        "control_objective": "Configure idle session timeout",
        "compliance_status": admin_timeout_compliance
    })
    
    remote_login_security_compliance = check_remote_login_security_port1(shell)
    compliance_results.append({
        "control_objective": "Ensure Remote Login Security is enabled for port1",
        "compliance_status": remote_login_security_compliance
    })

    remote_access_compliance = check_remote_access_limited(shell)
    compliance_results.append({
        "control_objective": "Ensure Remote access to devices is limited to a single management interface",
        "compliance_status": remote_access_compliance
    })

    trusted_hosts_compliance = check_trusted_hosts_subnet(shell)
    compliance_results.append({
        "control_objective": "Ensure 32-bit subnet mask is used for trusted hosts",
        "compliance_status": trusted_hosts_compliance
    })

    admin_lockout_compliance = check_admin_lockout_settings(shell)
    compliance_results.append({
        "control_objective": "Modify administrator account lockout duration and threshold values",
        "compliance_status": admin_lockout_compliance
    })

    banner_compliance = check_pre_login_banner(shell)
    compliance_results.append({
        "control_objective": "Ensure Banner is setup on admin accounts",
        "compliance_status": banner_compliance
    })

    maintainer_compliance = check_maintainer_account(shell)
    compliance_results.append({
        "control_objective": "Disable Maintainer Account",
        "compliance_status": maintainer_compliance
    })

    logging_compliance = check_logging_configuration(shell)
    compliance_results.append({
        "control_objective": "Make sure auditing and logging is configured",
        "compliance_status": logging_compliance
    })

    ntp_compliance = check_ntp_synchronization(shell)
    compliance_results.append({
        "control_objective": "Ensure System time is synchronizing with NTP Server",
        "compliance_status": ntp_compliance
    })

    password_ageing_compliance = check_password_ageing(shell)
    compliance_results.append({
        "control_objective": "Configure Password Ageing",
        "compliance_status": password_ageing_compliance
    })

    logging_compliance = check_logging_configuration(shell)
    compliance_results.append({
        "control_objective": "Configure logging on FortiWeb",
        "compliance_status": logging_compliance
    })

    syslog_compliance = check_syslog_server_configuration(shell)
    compliance_results.append({
        "control_objective": "Configure syslog server on FortiWeb",
        "compliance_status": syslog_compliance
    })

    email_compliance = check_alert_email_configuration(shell)
    compliance_results.append({
        "control_objective": "Enable Alert Email",
        "compliance_status": email_compliance
    })

    alert_severity_compliance = check_email_alert_severity(shell)
    compliance_results.append({
        "control_objective": "Ensure Trigger is configured to send alert email",
        "compliance_status": alert_severity_compliance
    })

    html_input_sanitization_compliance = check_html_input_sanitization(shell)
    compliance_results.append({
        "control_objective": "Ensure HTML application inputs are sanitized",
        "compliance_status": html_input_sanitization_compliance
    })

    http_methods_compliance = check_http_methods(shell)
    compliance_results.append({
        "control_objective": "Ensure only specific HTTP methods are allowed (if and only GET and POST are allowed)",
        "compliance_status": http_methods_compliance
    })

    https_redirection_compliance = check_https_redirection(shell)
    compliance_results.append({
        "control_objective": "Redirect the client to HTTPS connection forcefully",
        "compliance_status": https_redirection_compliance
    })

    waf_protection_compliance = check_waf_protection(shell)
    compliance_results.append({
        "control_objective": "Ensure that WAF is protecting against Known Attacks and data leaks",
        "compliance_status": waf_protection_compliance
    })

    cookie_protection_compliance = check_cookie_protection(shell)
    compliance_results.append({
        "control_objective": "Ensure protection for cookies poisoning is enabled",
        "compliance_status": cookie_protection_compliance
    })

    false_positives_compliance = check_false_positives(shell)
    compliance_results.append({
        "control_objective": "Reduce false positives",
        "compliance_status": false_positives_compliance
    })

    sql_injection_mitigation_compliance = check_sql_injection_mitigation(shell)
    compliance_results.append({
        "control_objective": "Enable false Positive Mitigation for SQL Injection signatures",
        "compliance_status": sql_injection_mitigation_compliance
    })

    dos_protection_compliance = check_dos_protection(shell)
    compliance_results.append({
        "control_objective": "Enable protection from DoS attacks",
        "compliance_status": dos_protection_compliance
    })

    ip_reputation_compliance = check_ip_reputation(shell)
    compliance_results.append({
        "control_objective": "Enable IP reputation for blacklisting/whitelisting clients",
        "compliance_status": ip_reputation_compliance
    })

    http_https_constraints_compliance = check_http_https_constraints(shell)
    compliance_results.append({
        "control_objective": "Enable HTTP/HTTPS protocol constraints",
        "compliance_status": http_https_constraints_compliance
    })

    machine_learning_compliance = check_machine_learning_enabled(shell)
    compliance_results.append({
        "control_objective": "Enable Machine Learning (Optional)",
        "compliance_status": machine_learning_compliance
    })

    unused_interfaces_compliance = check_unused_interfaces(shell)
    compliance_results.append({
        "control_objective": "Ensure unused interfaces are disabled",
        "compliance_status": unused_interfaces_compliance
    })

    os_firmware_update_compliance = check_os_firmware_update(shell)
    compliance_results.append({
        "control_objective": "Update OS and firmware",
        "compliance_status": os_firmware_update_compliance
    })

    automatic_signature_updates_compliance = check_automatic_signature_updates(shell)
    compliance_results.append({
        "control_objective": "Ensure Automatic signature updates are enabled",
        "compliance_status": automatic_signature_updates_compliance
    })

    restrict_local_policies_compliance = check_restrict_local_policies(shell)
    compliance_results.append({
        "control_objective": "Restrict Local Policies",
        "compliance_status": restrict_local_policies_compliance
    })

    access_list_compliance = check_access_list_explicit_deny(shell)
    compliance_results.append({
        "control_objective": "Ensure each access-list has an explicit deny statement",
        "compliance_status": access_list_compliance
    })

    domain_name_compliance = check_domain_name()
    compliance_results.append({
        "control_objective": "Set Domain name of Firewall",
        "compliance_status": domain_name_compliance
    })

    hostname_compliance = check_hostname_set(shell)
    compliance_results.append({
        "control_objective": "Set Host Name for Firewall",
        "compliance_status": hostname_compliance
    })










    # Write the results to CSV
    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
