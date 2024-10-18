import paramiko
import csv

def check_compliance():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Establish SSH connection
    try:
        client.connect('192.168.1.1', username='admin', password='your_password')
        
        commands = {
            'get_system_dns': 'get system dns',
            'show_intra_zone_traffic': 'show full-configuration system zone | grep -i intrazone',
            'show_pre_login_banner': 'show system global | grep -i pre-login-banner',
            'show_post_login_banner': 'show system global | grep -i post-login-banner',
            'get_time_zone': 'get system global | grep -i timezone'
        }

        compliance_results = []

        for key, command in commands.items():
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode().strip()
            compliance_status = check_output_compliance(key, output)
            compliance_results.append([key, compliance_status])

        # Write results to CSV
        with open('compliance_report.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Control Objective', 'Compliance Status'])
            writer.writerows(compliance_results)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        client.close()  # Ensure the SSH connection is closed

def check_output_compliance(command_key, output):
    # Compliance checks for each command output
    if command_key == 'get_system_dns':
        return "Compliant" if "8.8.8.8" in output else "Non-Compliant"
    
    elif command_key == 'show_intra_zone_traffic':
        return "Compliant" if "allow" in output.lower() else "Non-Compliant"
    
    elif command_key == 'show_pre_login_banner':
        return "Compliant" if "private computer system" in output.lower() else "Non-Compliant"
    
    elif command_key == 'show_post_login_banner':
        return "Compliant" if "private computer system" in output.lower() else "Non-Compliant"
    
    elif command_key == 'get_time_zone':
        return "Compliant" if "UTC" in output else "Non-Compliant"  # Adjust based on expected timezone

    return "Non-Compliant"  # Default non-compliance if no conditions match

if __name__ == "__main__":
    check_compliance()
