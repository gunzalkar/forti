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

def check_remote_login_security(shell):
    print("Checking remote login security settings...")
    interface_command = 'show system interface'
    output = execute_commands(shell, [interface_command])[0][1]
    
    # Check for 'allowaccess' settings
    lines = output.splitlines()
    for line in lines:
        if 'allowaccess:' in line:
            allowaccess_value = line.split(':')[1].strip()
            if allowaccess_value and allowaccess_value not in ["ssh https", "https ssh"]:
                print(f"Allowaccess is set to '{allowaccess_value}'. This is non-compliant.")
                return "Non-Compliant"
    
    print("Remote login security is configured correctly with only 'ssh https', 'https ssh', or is blank. This is compliant.")
    return "Compliant"











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
    # Check if the default admin account is removed
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

    remote_login_security_compliance = check_remote_login_security(shell)
    compliance_results.append({
        "control_objective": "Ensure Remote Login Security is enabled",
        "compliance_status": remote_login_security_compliance
    })










    # Write the results to CSV
    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
