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


# Function to check FortiAnalyzer/FortiManager log encryption settings
def check_fortianalyzer_encryption(shell):
    print("Executing FortiAnalyzer/FortiManager log encryption command...")
    log_encryption_command = 'end\nconfig log fortianalyzer setting\nget | grep -i enc\nend'
    output = execute_commands(shell, [log_encryption_command])[0][1]
    
    print("****************************************")
    print(output)

    print("Checking FortiAnalyzer/FortiManager log encryption settings...")
    if 'low' in output.lower():
        print("Log encryption is set to high.")
        return "Compliant"
    else:
        print("Log encryption is not set to high.")
        return "Non-Compliant"

# Example usage to add in the compliance results


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

    fortianalyzer_encryption_compliance = check_fortianalyzer_encryption(shell)
    compliance_results.append({
        "control_objective": "Encrypt Log Transmission to FortiAnalyzer / FortiManager",
        "compliance_status": fortianalyzer_encryption_compliance
    })


    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
