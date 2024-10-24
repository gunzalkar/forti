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

# Example compliance check for DNS settings
def check_dns_settings_fortiweb(shell):
    print("Executing DNS command...")
    dns_command = 'get system dns'
    output = execute_commands(shell, [dns_command])[0][1]
    
    print("Checking DNS settings...")
    dns_settings = {
        'primary': '8.8.8.8',
        'secondary': '8.8.4.4'
    }
    
    for key, value in dns_settings.items():
        pattern = fr"{key}\s*:\s*{value}"
        if not re.search(pattern, output):
            print(f"DNS setting mismatch: Expected {key} to be {value}")
            return "Non-Compliant"
    
    print("DNS settings are correct.")
    return "Compliant"

# Placeholder for other FortiWeb compliance checks
def check_firewall_settings(shell):
    print("Executing Firewall Settings check...")
    firewall_command = 'show firewall policy'
    output = execute_commands(shell, [firewall_command])[0][1]
    
    # Example pattern match for a FortiWeb specific check
    if 'set service "ALL"' in output:
        return "Non-Compliant"
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

    # DNS Check
    dns_compliance = check_dns_settings_fortiweb(shell)
    compliance_results.append({
        "control_objective": "Ensure DNS server is configured",
        "compliance_status": dns_compliance
    })

    # Firewall Policy Check
    firewall_compliance = check_firewall_settings(shell)
    compliance_results.append({
        "control_objective": "Ensure Firewall Policies are Correct",
        "compliance_status": firewall_compliance
    })

    # Write the results to CSV
    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
