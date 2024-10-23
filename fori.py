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

def check_event_logging(shell):
    print("Executing event logging command...")

    # Step 1: Enter 'config log eventfilter'
    enter_command = 'config log eventfilter'
    execute_commands(shell, [enter_command])

    # Step 2: Execute 'get | grep -i event'
    event_command = 'get | grep -i event'
    output = execute_commands(shell, [event_command])[0][1]
    print("****************************************")
    print(output)
    
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
    event_logging_compliance = check_event_logging(shell)
    compliance_results.append({
        "control_objective": "Enable Event Logging",
        "compliance_status": event_logging_compliance
    })



    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
