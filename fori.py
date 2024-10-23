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

def check_auth_lock_settings(shell):
    print("Executing auth-lockout command...")
    
    # Step 1: Enter 'config user setting'
    enter_command = 'config user setting'
    execute_commands(shell, [enter_command])

    # Step 2: Execute 'get | grep -i auth-lock'
    auth_lock_command = 'get | grep -i auth-lock'
    output = execute_commands(shell, [auth_lock_command])[0][1]
    print("****************************************")
    print(output)
    
    # Step 3: Exit the config mode using 'end'
    exit_command = 'end'
    execute_commands(shell, [exit_command])

    print("Checking auth-lockout settings...")
    
    # Use regex to check for auth-lockout-threshold and auth-lockout-duration with varying spaces
    threshold_pattern = r"auth-lockout-threshold\s*:\s*5"
    duration_pattern = r"auth-lockout-duration\s*:\s*300"

    # Check if both patterns exist in the output
    if re.search(threshold_pattern, output) and re.search(duration_pattern, output):
        print("Auth-lockout settings are correct.")
        return "Compliant"
    else:
        print("Auth-lockout settings mismatch: Expected threshold and duration.")
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
import re



# Example usage to add to the compliance results
    auth_lock_compliance = check_auth_lock_settings(shell)
    compliance_results.append({
        "control_objective": "Configuring the maximum login attempts and lockout period",
        "compliance_status": auth_lock_compliance
    })



    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
