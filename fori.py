import paramiko
import re
import csv

# Function to execute multiple commands on the FortiGate device
def execute_commands(client, commands):
    results = []
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8')
        results.append((command, output))
    return results

# Function to check DNS settings
def check_dns_settings(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to connect to the FortiGate device...")
        client.connect(hostname, username=username, password=password)
        print("SSH connection successful.")
        
        # Send initial command to press 'a' and then enter
        commands = ['a', 'get system dns']
        print("Sending initial command and executing DNS command...")
        outputs = execute_commands(client, commands)
        
        dns_output = outputs[1][1]
        
        print("Checking DNS settings...")
        dns_settings = {
            'primary': '8.8.8.8',
            'secondary': '8.8.4.4'
        }
        
        for key, value in dns_settings.items():
            pattern = fr"{key}\s*:\s*{value}"
            if not re.search(pattern, dns_output):
                print(f"DNS setting mismatch: Expected {key} to be {value}")
                return "Non-Compliant"
        
        print("DNS settings are correct.")
        return "Compliant"
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return "Non-Compliant"
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return "Non-Compliant"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Non-Compliant"
    finally:
        client.close()

# Function to check intra-zone traffic configuration
def check_intrazone_traffic(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to connect to the FortiGate device...")
        client.connect(hostname, username=username, password=password)
        print("SSH connection successful.")
        
        # Send initial command to press 'a' and then enter
        commands = ['a', 'show full-configuration system zone | grep -i intrazone']
        print("Sending initial command and executing intra-zone traffic command...")
        outputs = execute_commands(client, commands)
        
        intrazone_output = outputs[1][1]
        
        print("Checking intra-zone traffic configuration...")
        if 'set intrazone deny' in intrazone_output:
            print("Intra-zone traffic is correctly configured as denied.")
            return "Compliant"
        else:
            print("Intra-zone traffic is not configured as denied.")
            return "Non-Compliant"
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return "Non-Compliant"
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return "Non-Compliant"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Non-Compliant"
    finally:
        client.close()

# Function to check Pre-Login Banner configuration
def check_pre_login_banner(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to connect to the FortiGate device...")
        client.connect(hostname, username=username, password=password)
        print("SSH connection successful.")
        
        # Send initial command to press 'a' and then enter
        commands = ['a', 'show system global | grep -i pre-login-banner']
        print("Sending initial command and executing Pre-Login Banner command...")
        outputs = execute_commands(client, commands)
        
        pre_login_output = outputs[1][1]
        
        print("Checking Pre-Login Banner configuration...")
        if 'enable' in pre_login_output.lower():
            print("Pre-Login Banner is set.")
            return "Compliant"
        else:
            print("Pre-Login Banner is not set.")
            return "Non-Compliant"
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return "Non-Compliant"
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return "Non-Compliant"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Non-Compliant"
    finally:
        client.close()

# Function to check Post-Login Banner configuration
def check_post_login_banner(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to connect to the FortiGate device...")
        client.connect(hostname, username=username, password=password)
        print("SSH connection successful.")
        
        # Send initial command to press 'a' and then enter
        commands = ['a', 'show system global | grep -i post-login-banner']
        print("Sending initial command and executing Post-Login Banner command...")
        outputs = execute_commands(client, commands)
        
        post_login_output = outputs[1][1]
        
        print("Checking Post-Login Banner configuration...")
        if 'enable' in post_login_output.lower():
            print("Post-Login Banner is set.")
            return "Compliant"
        else:
            print("Post-Login Banner is not set.")
            return "Non-Compliant"
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return "Non-Compliant"
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return "Non-Compliant"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Non-Compliant"
    finally:
        client.close()

def check_timezone(hostname, username, password, timezone):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to connect to the FortiGate device...")
        client.connect(hostname, username=username, password=password)
        print("SSH connection successful.")
        
        # Send initial command to press 'a' and then enter
        commands = ['a', f'get system global | grep -i timezone']
        print("Sending initial command and executing Timezone command...")
        outputs = execute_commands(client, commands)
        
        timezone_output = outputs[1][1]
        
        print("Checking timezone configuration...")
        if timezone.lower() in timezone_output.lower():
            print("Timezone is properly configured.")
            return "Compliant"
        else:
            print(f"Timezone is not properly configured. Expected: {timezone}.")
            return "Non-Compliant"
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return "Non-Compliant"
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return "Non-Compliant"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Non-Compliant"
    finally:
        client.close()




##############################################################
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
timezone = rf"Asia/Kolkata"

# List to store compliance results
compliance_results = []

# Check DNS compliance
dns_compliance = check_dns_settings(hostname, username, password)
compliance_results.append({
    "control_objective": "Ensure DNS server is configured",
    "compliance_status": dns_compliance
})

# Check intra-zone traffic compliance
intrazone_compliance = check_intrazone_traffic(hostname, username, password)
compliance_results.append({
    "control_objective": "Ensure intra-zone traffic is not always allowed",
    "compliance_status": intrazone_compliance
})

# Check Pre-Login Banner compliance
pre_login_banner_compliance = check_pre_login_banner(hostname, username, password)
compliance_results.append({
    "control_objective": "Ensure 'Pre-Login Banner' is set",
    "compliance_status": pre_login_banner_compliance
})

# Check Post-Login Banner compliance
post_login_banner_compliance = check_post_login_banner(hostname, username, password)
compliance_results.append({
    "control_objective": "Ensure 'Post-Login Banner' is set",
    "compliance_status": post_login_banner_compliance
})

timezone_compliance = check_timezone(hostname, username, password, timezone)
compliance_results.append({
    "control_objective": "Ensure timezone is properly configured",
    "compliance_status": timezone_compliance
})

# Write results to CSV
write_to_csv(compliance_results)
print("Compliance report has been written to 'compliance_report.csv'.")
