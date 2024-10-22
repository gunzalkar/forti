import paramiko
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

# Function to check Centralized Logging and Reporting settings
def check_centralized_logging(shell):
    # Check first command: get log setting
    print("Executing 'get log setting' command...")
    log_setting_command = 'get log setting'
    log_setting_output = execute_commands(shell, [log_setting_command])[0][1]
    
    print("****************************************")
    print(log_setting_output)

    # Check if 'disable' exists in the output (case-insensitive)
    if re.search(r'\bdisable\b', log_setting_output, re.IGNORECASE):
        print("Log setting contains 'disable'. This is Non-Compliant.")
        return "Non-Compliant"

    # Check second command: get log syslogd setting
    print("Executing 'get log syslogd setting' command...")
    syslogd_setting_command = 'get log syslogd setting'
    syslogd_setting_output = execute_commands(shell, [syslogd_setting_command])[0][1]
    
    print("****************************************")
    print(syslogd_setting_output)

    # Check if 'status' is 'enable' (ignore spaces)
    if not re.search(r'status\s*:\s*enable', syslogd_setting_output, re.IGNORECASE):
        print("Syslogd setting is not enabled. This is Non-Compliant.")
        return "Non-Compliant"

    # Check third command: get log fortianalyzer setting
    print("Executing 'get log fortianalyzer setting' command...")
    fortianalyzer_setting_command = 'get log fortianalyzer setting'
    fortianalyzer_setting_output = execute_commands(shell, [fortianalyzer_setting_command])[0][1]
    
    print("****************************************")
    print(fortianalyzer_setting_output)

    # Check if 'status' is 'enable' (ignore spaces)
    if not re.search(r'status\s*:\s*enable', fortianalyzer_setting_output, re.IGNORECASE):
        print("FortiAnalyzer setting is not enabled. This is Non-Compliant.")
        return "Non-Compliant"

    # If all checks are compliant
    print("All log settings are Compliant.")
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
