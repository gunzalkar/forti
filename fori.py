import paramiko
import re
import csv
import time

def execute_commands(client, commands):
    shell = client.invoke_shell()
    time.sleep(1)
    outputs = []
    
    for command in commands:
        shell.send(command + '\n')
        time.sleep(2)  # Allow time for the command to execute
        
        # Read output and handle POST WARNING
        output = ''
        while True:
            time.sleep(1)
            output += shell.recv(65535).decode('utf-8')
            if "Press 'a' to accept" in output:
                shell.send('a\n')  # Accept the warning
                time.sleep(2)  # Allow time for the acceptance
            if output.endswith('# '):  # End of command prompt
                break
        
        outputs.append((command, output))
        print(f"Command: {command}\nOutput:\n{output}\n{'-' * 50}")  # Log command and output
    
    return outputs


def check_dns_settings(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    client.connect(hostname, username=username, password=password)
    execute_commands(client, ['a'])  # Send 'a' to accept the warning

    commands = ['get system dns']
    outputs = execute_commands(client, commands)
    dns_output = outputs[0][1]

    dns_settings = {'primary': '8.8.8.8', 'secondary': '8.8.4.4'}
    for key, value in dns_settings.items():
        if not re.search(fr"{key}\s*:\s*{value}", dns_output):
            return "Non-Compliant"
    return "Compliant"

def check_intrazone_traffic(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    client.connect(hostname, username=username, password=password)
    execute_commands(client, ['a'])  # Send 'a' to accept the warning

    commands = ['show full-configuration system zone | grep -i intrazone']
    outputs = execute_commands(client, commands)
    intrazone_output = outputs[0][1]
    
    return "Compliant" if 'set intrazone deny' in intrazone_output else "Non-Compliant"

def check_pre_login_banner(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    client.connect(hostname, username=username, password=password)
    execute_commands(client, ['a'])  # Send 'a' to accept the warning

    commands = ['show system global | grep -i pre-login-banner']
    outputs = execute_commands(client, commands)
    pre_login_output = outputs[0][1]

    return "Compliant" if 'enable' in pre_login_output.lower() else "Non-Compliant"

def check_post_login_banner(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    client.connect(hostname, username=username, password=password)
    execute_commands(client, ['a'])  # Send 'a' to accept the warning

    commands = ['show system global | grep -i post-login-banner']
    outputs = execute_commands(client, commands)
    post_login_output = outputs[0][1]

    return "Compliant" if 'enable' in post_login_output.lower() else "Non-Compliant"

def check_timezone(hostname, username, password, timezone):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    client.connect(hostname, username=username, password=password)
    execute_commands(client, ['a'])  # Send 'a' to accept the warning

    commands = ['get system global | grep -i timezone']
    outputs = execute_commands(client, commands)
    timezone_output = outputs[0][1]

    return "Compliant" if timezone.lower() in timezone_output.lower() else "Non-Compliant"

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

compliance_results = []

compliance_results.append({
    "control_objective": "Ensure DNS server is configured",
    "compliance_status": check_dns_settings(hostname, username, password)
})

compliance_results.append({
    "control_objective": "Ensure intra-zone traffic is not always allowed",
    "compliance_status": check_intrazone_traffic(hostname, username, password)
})

compliance_results.append({
    "control_objective": "Ensure 'Pre-Login Banner' is set",
    "compliance_status": check_pre_login_banner(hostname, username, password)
})

compliance_results.append({
    "control_objective": "Ensure 'Post-Login Banner' is set",
    "compliance_status": check_post_login_banner(hostname, username, password)
})

timezone = rf"Asia/Kolkata"
compliance_results.append({
    "control_objective": "Ensure timezone is properly configured",
    "compliance_status": check_timezone(hostname, username, password, timezone)
})

write_to_csv(compliance_results)
