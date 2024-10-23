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

def check_antivirus_updates(shell):
    print("Checking Antivirus Definition Push Updates...")

    # Step 1: Execute 'config system autoupdate schedule'
    schedule_command = 'config system autoupdate schedule'
    execute_commands(shell, [schedule_command])

    # Step 2: Show the configuration and capture the output
    show_schedule_command = 'show'
    schedule_output = execute_commands(shell, [show_schedule_command])[0][1]
    print("****************************************")
    print(schedule_output)

    # Step 3: Exit the config mode for schedule
    exit_command = 'end'
    execute_commands(shell, [exit_command])

    # Step 4: Execute 'config system autoupdate tunneling'
    tunneling_command = 'config system autoupdate tunneling'
    execute_commands(shell, [tunneling_command])

    # Step 5: Show the configuration for tunneling and capture the output
    show_tunneling_command = 'show'
    tunneling_output = execute_commands(shell, [show_tunneling_command])[0][1]
    print("****************************************")
    print(tunneling_output)

    # Step 6: Exit the config mode for tunneling
    execute_commands(shell, [exit_command])

    print("Checking if Antivirus Definition Push Updates are configured...")

    # Regex pattern to check for 'set status enable' in both outputs
    status_pattern = r"\bset status enable\b"

    # Check if 'set status enable' exists in either output
    if re.search(status_pattern, schedule_output, re.IGNORECASE) or re.search(status_pattern, tunneling_output, re.IGNORECASE):
        print("Antivirus Definition Push Updates are configured.")
        return "Compliant"
    else:
        print("Antivirus Definition Push Updates are not configured.")
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

    antivirus_updates_compliance = check_antivirus_updates(shell)
    compliance_results.append({
        "control_objective": "Ensure Antivirus Definition Push Updates are Configured",
        "compliance_status": antivirus_updates_compliance
    })




    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
