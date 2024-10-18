import paramiko

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
            if f"{key}             : {value}" not in output:
                print(f"DNS setting mismatch: Expected {key} to be {value}")
                return False
        
        print("DNS settings are correct.")
        return True
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
        return False
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        client.close()

# Example usage
hostname = 'your_fortigate_ip'
username = 'your_username'
password = 'your_password'

result = check_dns_settings(hostname, username, password)
if result:
    print("DNS settings are as expected.")
else:
    print("DNS settings verification failed.")
