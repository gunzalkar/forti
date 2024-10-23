import paramiko # type: ignore
import re
import csv
import time
import re

# Function to execute multiple commands on the FortiGate device
def execute_commands(shell, commands):
    results = []
    for command in commands:
        shell.send(command + '\n')
        time.sleep(1)  # Wait for the command to execute
        output = shell.recv(65535).decode('utf-8')
        results.append((command, output))
    return results

# Function to connect to FortiGate and send acceptance command
def connect_to_fortigate(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to connect to the FortiGate device...")
        client.connect(hostname, username=username, password=password)
        print("SSH connection successful.")
        
        # Create an interactive shell
        shell = client.invoke_shell()
        
        # Wait for the pre-login banner
        time.sleep(2)
        
        # Send 'a' to accept the warning
        shell.send('a\n')
        time.sleep(1)  # Wait for the acceptance to process
        
        return shell
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return None
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

import re

def check_security_fabric():
    print("Manual check needed: Ensure Security Fabric is configured.")
    return "Manual check needed"

def check_trusted_signed_certificate():
    print("Manual check needed: Apply a Trusted Signed Certificate for VPN Portal.")
    return "Manual check needed"

def check_auth_lock_settings(shell):
    print("Executing auth-lockout command...")
    enter_command = 'config user setting'
    execute_commands(shell, [enter_command])
    auth_lock_command = 'get | grep -i auth-lock'
    output = execute_commands(shell, [auth_lock_command])[0][1]
    print("****************************************")
    print(output)
    exit_command = 'end'
    execute_commands(shell, [exit_command])
    print("Checking auth-lockout settings...")
    threshold_pattern = r"auth-lockout-threshold\s*:\s*5"
    duration_pattern = r"auth-lockout-duration\s*:\s*300"
    if re.search(threshold_pattern, output) and re.search(duration_pattern, output):
        print("Auth-lockout settings are correct.")
        return "Compliant"
    else:
        print("Auth-lockout settings mismatch: Expected threshold and duration.")
        return "Non-Compliant"
    
def check_event_logging(shell):
    print("Executing event logging command...")

    # Step 1: Enter 'config log eventfilter'
    enter_command = 'config log eventfilter'
    execute_commands(shell, [enter_command])

    # Step 2: Execute 'get | grep -i event'
    event_command = 'get | grep -i event'
    output = execute_commands(shell, [event_command])[0][1]

    # Step 3: Exit the config mode using 'end'
    exit_command = 'end'
    execute_commands(shell, [exit_command])

    print("Checking event logging settings...")

    # Use regex to check for the word 'enable' with varying spaces
    event_logging_pattern = r"\benable\b"

    # Check if the word 'enable' exists in the output
    if re.search(event_logging_pattern, output, re.IGNORECASE):
        print("Event logging is enabled.")
        return "Compliant"
    else:
        print("Event logging is not enabled.")
        return "Non-Compliant"
    
def check_fortianalyzer_encryption(shell):
    print("Executing FortiAnalyzer encryption command...")
    enter_command = 'config log fortianalyzer setting'
    execute_commands(shell, [enter_command])
    enc_command = 'get | grep -i enc'
    output = execute_commands(shell, [enc_command])[0][1]
    exit_command = 'end'
    execute_commands(shell, [exit_command])
    print("Checking FortiAnalyzer encryption settings...")
    encryption_pattern = r"\bhigh\b"
    if re.search(encryption_pattern, output, re.IGNORECASE):
        print("FortiAnalyzer encryption is set to high.")
        return "Compliant"
    else:
        print("FortiAnalyzer encryption is not set to high.")
        return "Non-Compliant"
    
def check_centralized_logging(shell):
    print("Checking Centralized Logging and Reporting...")

    
    log_setting_command = 'get log setting'
    output_log_setting = execute_commands(shell, [log_setting_command])[0][1]
    print("Log Setting Output:")
    print(output_log_setting)

    
    if re.search(r"\bdisable\b", output_log_setting, re.IGNORECASE):
        print("Log setting contains 'disable'.")
        return "Non-Compliant (Manual Check Suggested)"
    else:
        print("Log setting does not contain 'disable'.")

   
    log_syslogd_command = 'get log syslogd setting'
    output_log_syslogd = execute_commands(shell, [log_syslogd_command])[0][1]
    print("Syslogd Setting Output:")
    print(output_log_syslogd)

    
    if re.search(r"status\s*:\s*enable", output_log_syslogd, re.IGNORECASE):
        print("Syslogd status is enabled.")
    else:
        print("Syslogd status is not enabled.")
        return "Non-Compliant (Manual Check Suggested)"

    log_fortianalyzer_command = 'get log fortianalyzer setting'
    output_log_fortianalyzer = execute_commands(shell, [log_fortianalyzer_command])[0][1]
    print("FortiAnalyzer Setting Output:")
    print(output_log_fortianalyzer)

    if re.search(r"status\s*:\s*enable", output_log_fortianalyzer, re.IGNORECASE):
        print("FortiAnalyzer status is enabled.")
    else:
        print("FortiAnalyzer status is not enabled.")
        return "Non-Compliant (Manual Check Suggested)"

    # If all conditions are met, the check is compliant
    print("Centralized Logging and Reporting is compliant.")
    return "Compliant (Manual Check Suggested)"


def check_dns_filter_policy(shell):
    print("Manual check needed:DNS Filter.")
    
    # Indicate that a manual check is required
    return "Manual check needed"







def write_to_csv(compliance_results):
    with open('compliance_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Sr No.", "Control Objective", "Compliance Status"])
        for index, result in enumerate(compliance_results, start=1):
            writer.writerow([index, result['control_objective'], result['compliance_status']])

hostname = '192.168.1.1'
username = 'admin'
password = 'password@Gat1'
timezone = rf"Asia/Kolkata"
host_name = "New_FGT1"
shell = connect_to_fortigate(hostname, username, password)

if shell:
    compliance_results = []

    security_fabric_compliance = check_security_fabric()
    compliance_results.append({
        "control_objective": "Ensure Security Fabric is Configured",
        "compliance_status": security_fabric_compliance
    })

    trusted_signed_certificate_compliance = check_trusted_signed_certificate()
    compliance_results.append({
        "control_objective": "Apply a Trusted Signed Certificate for VPN Portal",
        "compliance_status": trusted_signed_certificate_compliance
    })

    auth_lock_compliance = check_auth_lock_settings(shell)
    compliance_results.append({
        "control_objective": "Configuring the maximum login attempts and lockout period",
        "compliance_status": auth_lock_compliance
    })


    event_logging_compliance = check_event_logging(shell)
    compliance_results.append({
        "control_objective": "Enable Event Logging",
        "compliance_status": event_logging_compliance
    })

    fortianalyzer_encryption_compliance = check_fortianalyzer_encryption(shell)
    compliance_results.append({
        "control_objective": "Encrypt Log Transmission to FortiAnalyzer / FortiManager",
        "compliance_status": fortianalyzer_encryption_compliance
    })

    centralized_logging_compliance = check_centralized_logging(shell)
    compliance_results.append({
        "control_objective": "Centralized Logging and Reporting",
        "compliance_status": centralized_logging_compliance
    })

    dns_check_policy = check_dns_filter_policy(shell)
    compliance_results.append({
        "control_objective": "Apply DNS Filter Security Profile to Policies",
        "compliance_status": dns_check_policy
    })
    # Example usage to add to the compliance results





    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
