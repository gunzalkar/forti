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

def check_antivirus_updates(shell):
    print("Executing antivirus update commands...")

    # Step 1: Run 'config system autoupdate schedule', then 'show', and 'end'
    schedule_command = 'config system autoupdate schedule'
    show_schedule_command = 'show'
    end_command = 'end'

    # Execute the commands one by one
    execute_commands(shell, [schedule_command])
    schedule_output = execute_commands(shell, [show_schedule_command])[0][1]
    execute_commands(shell, [end_command])
    print("****************************************")
    print("Schedule Output:")
    print(schedule_output)

    # Step 2: Run 'config system autoupdate tunneling', then 'show', and 'end'
    tunneling_command = 'config system autoupdate tunneling'

    # Execute the commands one by one
    execute_commands(shell, [tunneling_command])
    tunneling_output = execute_commands(shell, [show_schedule_command])[0][1]
    execute_commands(shell, [end_command])
    print("****************************************")
    print("Tunneling Output:")
    print(tunneling_output)
    
    # Pattern to check for 'set status enable' with flexible spacing
    status_pattern = r"set\s+status\s+enable"

    # Step 3: Check if 'set status enable' is found in both outputs
    if re.search(status_pattern, schedule_output, re.IGNORECASE) and re.search(status_pattern, tunneling_output, re.IGNORECASE):
        print("Antivirus definition push updates are configured correctly.")
        return "Compliant"
    else:
        print("Antivirus definition push updates are not configured correctly.")
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

    # Example usage to add to the compliance results
    antivirus_compliance = check_antivirus_updates(shell)
    compliance_results.append({
        "control_objective": "Ensure Antivirus Definition Push Updates are Configured",
        "compliance_status": antivirus_compliance
    })





    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
