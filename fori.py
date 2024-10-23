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

import re

def check_centralized_logging(shell):
    print("Checking Centralized Logging and Reporting...")

    # Step 1: Execute 'get log setting'
    log_setting_command = 'get log setting'
    output_log_setting = execute_commands(shell, [log_setting_command])[0][1]
    print("Log Setting Output:")
    print(output_log_setting)

    # Check for the word 'disable' in 'get log setting'
    if re.search(r"\bdisable\b", output_log_setting, re.IGNORECASE):
        print("Log setting contains 'disable'.")
        return "Non-Compliant"
    else:
        print("Log setting does not contain 'disable'.")

    # Step 2: Execute 'get log syslogd setting'
    log_syslogd_command = 'get log syslogd setting'
    output_log_syslogd = execute_commands(shell, [log_syslogd_command])[0][1]
    print("Syslogd Setting Output:")
    print(output_log_syslogd)

    # Check if 'status: enable' is present in 'get log syslogd setting'
    if re.search(r"status\s*:\s*enable", output_log_syslogd, re.IGNORECASE):
        print("Syslogd status is enabled.")
    else:
        print("Syslogd status is not enabled.")
        return "Non-Compliant"

    # Step 3: Execute 'get log fortianalyzer setting'
    log_fortianalyzer_command = 'get log fortianalyzer setting'
    output_log_fortianalyzer = execute_commands(shell, [log_fortianalyzer_command])[0][1]
    print("FortiAnalyzer Setting Output:")
    print(output_log_fortianalyzer)

    # Check if 'status: enable' is present in 'get log fortianalyzer setting'
    if re.search(r"status\s*:\s*enable", output_log_fortianalyzer, re.IGNORECASE):
        print("FortiAnalyzer status is enabled.")
    else:
        print("FortiAnalyzer status is not enabled.")
        return "Non-Compliant"

    # If all conditions are met, the check is compliant
    print("Centralized Logging and Reporting is compliant.")
    return "Compliant"






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

    # Example usage to add to the compliance results
    centralized_logging_compliance = check_centralized_logging(shell)
    compliance_results.append({
        "control_objective": "Centralized Logging and Reporting",
        "compliance_status": centralized_logging_compliance
    })




    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
