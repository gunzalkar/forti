import paramiko

def check_dns_settings(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(hostname, username=username, password=password)
        stdin, stdout, stderr = client.exec_command('get system dns')
        output = stdout.read().decode('utf-8')
        
        dns_settings = {
            'primary': '8.8.8.8',
            'secondary': '8.8.4.4'
        }
        
        for key, value in dns_settings.items():
            if f"{key}             : {value}" not in output:
                return False
        return True
    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        client.close()

# Example usage
hostname = '192.168.1.1'
username = 'admin'
password = 'password'

result = check_dns_settings(hostname, username, password)
print(result)
