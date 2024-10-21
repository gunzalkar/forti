import paramiko
import re
import csv
import time

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

# Function to check DNS settings
def check_dns_settings(shell):
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

# Function to check intra-zone traffic configuration
def check_intrazone_traffic(shell):
    print("Executing intra-zone traffic command...")
    intrazone_command = 'show full-configuration system zone | grep -i intrazone'
    output = execute_commands(shell, [intrazone_command])[0][1]
    
    print("Checking intra-zone traffic configuration...")
    if 'set intrazone deny' in output:
        print("Intra-zone traffic is correctly configured as denied.")
        return "Compliant"
    else:
        print("Intra-zone traffic is not configured as denied.")
        return "Non-Compliant"

# Function to check Pre-Login Banner configuration
def check_pre_login_banner(shell):
    print("Executing Pre-Login Banner command...")
    pre_login_command = 'show system global | grep -i pre-login-banner'
    output = execute_commands(shell, [pre_login_command])[0][1]
    
    print("Checking Pre-Login Banner configuration...")
    if 'enable' in output.lower():
        print("Pre-Login Banner is set.")
        return "Compliant"
    else:
        print("Pre-Login Banner is not set.")
        return "Non-Compliant"

# Function to check Post-Login Banner configuration
def check_post_login_banner(shell):
    print("Executing Post-Login Banner command...")
    post_login_command = 'show system global | grep -i post-login-banner'
    output = execute_commands(shell, [post_login_command])[0][1]
    
    print("Checking Post-Login Banner configuration...")
    if 'enable' in output.lower():
        print("Post-Login Banner is set.")
        return "Compliant"
    else:
        print("Post-Login Banner is not set.")
        return "Non-Compliant"

# Function to check Timezone configuration
def check_timezone_configuration(shell, timezone):
    print("Executing timezone command...")
    timezone_command = 'get system global | grep -i timezone'
    output = execute_commands(shell, [timezone_command])[0][1]
    
    print("Checking timezone configuration...")
    if timezone.lower() in output.lower():
        print("Timezone is properly configured.")
        return "Compliant"
    else:
        print("Timezone is not configured correctly.")
        return "Non-Compliant"

# Function to write compliance status to a CSV file
def write_to_csv(compliance_results):
    with open('compliance_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Sr No.", "Control Objective", "Compliance Status"])
        for index, result in enumerate(compliance_results, start=1):
            writer.writerow([index, result['control_objective'], result['compliance_status']])

# Example usage
hostname = '192.168.1.1'
username = 'admin'
password = 'password'
timezone = rf"Asia/Kolkata"  # Define the timezone variable

# Connect to FortiGate
shell = connect_to_fortigate(hostname, username, password)

if shell:
    # List to store compliance results
    compliance_results = []

    # Check DNS compliance
    dns_compliance = check_dns_settings(shell)
    compliance_results.append({
        "control_objective": "Ensure DNS server is configured",
        "compliance_status": dns_compliance
    })

    # Check intra-zone traffic compliance
    intrazone_compliance = check_intrazone_traffic(shell)
    compliance_results.append({
        "control_objective": "Ensure intra-zone traffic is not always allowed",
        "compliance_status": intrazone_compliance
    })

    # Check Pre-Login Banner compliance
    pre_login_banner_compliance = check_pre_login_banner(shell)
    compliance_results.append({
        "control_objective": "Ensure 'Pre-Login Banner' is set",
        "compliance_status": pre_login_banner_compliance
    })

    # Check Post-Login Banner compliance
    post_login_banner_compliance = check_post_login_banner(shell)
    compliance_results.append({
        "control_objective": "Ensure 'Post-Login Banner' is set",
        "compliance_status": post_login_banner_compliance
    })

    # Check Timezone compliance
    timezone_compliance = check_timezone_configuration(shell, timezone)
    compliance_results.append({
        "control_objective": "Ensure timezone is properly configured",
        "compliance_status": timezone_compliance
    })

    # Write results to CSV
    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    # Close the shell connection
    shell.close()
