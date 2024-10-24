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

    # Check if the default admin account is removed
    admin_compliance = check_default_admin_removed(shell)
    compliance_results.append({
        "control_objective": "Ensure Default admin account is removed and New Super admin account has been configured",
        "compliance_status": admin_compliance
    })


    # Write the results to CSV
    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
