import paramiko
import re
import csv

# Function to check DNS settings
def check_dns_settings(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to connect to the FortiGate device...")
        client.connect(hostname, username=username, password=password)
        print("SSH connection successful.")
        
        stdin, stdout, stderr = client.exec_command('get system dns')
        output = stdout.read().decode('utf-8')
        
        print("Checking DNS settings...")
        dns_settings = {
            'primary': '8.8.8.8',
            'secondary': '8.8.4.4'
        }
        
        for key, value in dns_settings.items():
            pattern = fr"{key}\s*:\s*{value}"
            if not re.search(pattern, output):
                print(f"DNS setting mismatch: Expected {key} to be {value}")
                return "Non-Compliance"
        
        print("DNS settings are correct.")
        return "Compliance"
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return "Non-Compliance"
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return "Non-Compliance"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Non-Compliance"
    finally:
        client.close()

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

# List to store compliance results
compliance_results = []

# Check DNS compliance
dns_compliance = check_dns_settings(hostname, username, password)
compliance_results.append({
    "control_objective": "Ensure DNS server is configured",
    "compliance_status": dns_compliance
})

# Add more compliance checks here in the future...

# Write results to CSV
write_to_csv(compliance_results)
print("Compliance report has been written to 'compliance_report.csv'.")
