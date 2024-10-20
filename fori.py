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
    
# Function to check NTP synchronization
def check_ntp_status(shell):
    print("Executing NTP status command...")
    ntp_command = 'diagnose sys ntp status'
    output = execute_commands(shell, [ntp_command])[0][1]
    
    print("Checking NTP synchronization status...")
    required_strings = ['synchronized: no', 'ntpsync: enabled', 'server-mode: enabled']
    
    if all(item in output.lower() for item in required_strings):
        print("NTP is properly configured.")
        return "Compliant"
    else:
        print("NTP is not properly configured.")
        return "Non-Compliant"

def check_hostname(shell, host_name):
    print("Executing Hostname command...")
    host_name_command = 'get system global | grep -i hostname'
    output = execute_commands(shell, [host_name_command])[0][1]
    
    print("Checking Hostname configuration...")
    if host_name.lower() in output.lower():
        print("Hostname is properly configured.")
        return "Compliant"
    else:
        print("Hostname is not configured correctly.")
        return "Non-Compliant"

def check_firmware_manual():
    print("Firmware check requires a manual review.")
    return "Manual Check Needed"

# Function to check USB firmware and configuration installation status
def check_auto_install(shell):
    print("Executing auto-install configuration check...")
    auto_install_commands = ['config system auto-install', 'get']
    output = execute_commands(shell, auto_install_commands)[1][1]
    
    print("Checking auto-install configuration settings...")
    required_settings = ['auto-install-config : disable', 'auto-install-image  : disable']
    
    if all(setting in output.lower() for setting in required_settings):
        print("USB Firmware and configuration installation is disabled.")
        return "Compliant"
    else:
        print("USB Firmware and configuration installation is not properly disabled.")
        return "Non-Compliant"

# Function to check USB firmware and configuration installation status
def check_tls_static_keys(shell):
    print("Executing TLS static key ciphers command...")
    auto_install_commands = ['end', 'get system global | grep -i ssl-static-key-ciphers']
    output = execute_commands(shell, auto_install_commands)[1][1]
    print(output)
    
    print("Checking TLS static keys configuration...")
    if 'ssl-static-key-ciphers: disable' in output.lower():
        print("Static keys for TLS are disabled.")
        return "Compliant"
    else:
        print("Static keys for TLS are not disabled.")
        return "Non-Compliant"

# Function to check if global strong encryption is enabled
def check_global_strong_encryption(shell):
    print("Executing global strong encryption command...")
    crypto_command = 'get system global | grep -i crypto'
    output = execute_commands(shell, [crypto_command])[0][1]

    print("Checking global strong encryption configuration...")
    if 'enable' in output.lower():
        print("Global strong encryption is enabled.")
        return "Compliant"
    else:
        print("Global strong encryption is not enabled.")
        return "Non-Compliant"

# Function to check if the password policy is enabled and correctly configured
def check_password_policy(shell):
    print("Executing password policy command...")
    password_policy_command = 'get system password-policy'
    output = execute_commands(shell, [password_policy_command])[0][1]

    print("Checking password policy configuration...")
    required_settings = {
        'status              : enable',
        'apply-to            : admin-password ipsec-preshared-key',
        'minimum-length      : 8',
        'min-lower-case-letter: 1',
        'min-upper-case-letter: 1',
        'min-non-alphanumeric: 1',
        'min-number          : 1',
        'min-change-characters: 0',
        'expire-status       : enable',
        'expire-day          : 90',
        'reuse-password      : disable'
    }
    
    if all(setting in output for setting in required_settings):
        print("Password policy is enabled and correctly configured.")
        return "Compliant"
    else:
        print("Password policy is not properly configured.")
        return "Non-Compliant"

# Function to check if administrator password retries and lockout time are configured
def check_admin_lockout(shell):
    print("Executing admin lockout command...")
    lockout_command = 'get system global | grep -i admin-lockout'
    output = execute_commands(shell, [lockout_command])[0][1]

    print("Checking administrator password retries and lockout time configuration...")
    required_settings = {
        'admin-lockout-duration: 60',
        'admin-lockout-threshold: 3'
    }
    
    if all(setting in output.lower() for setting in required_settings):
        print("Administrator password retries and lockout time are correctly configured.")
        return "Compliant"
    else:
        print("Administrator password retries and/or lockout time are not properly configured.")
        return "Non-Compliant"

# Function to check if the SNMP agent is disabled
def check_snmp_agent(shell):
    print("Configuring SNMP sysinfo...")
    shell.send('end\n')
    shell.send('config system snmp sysinfo\n')
    time.sleep(1)  # Wait for command to execute

    print("Executing command to check SNMP status...")
    status_command = 'show full | grep -i status'
    output = execute_commands(shell, [status_command])[0][1]

    # Send the 'end' command to exit the configuration mode
    shell.send('end\n')
    time.sleep(1)  # Wait for command to execute

    print("Checking SNMP agent status...")
    if 'disable' in output.lower():
        print("SNMP agent is disabled.")
        return "Compliant"
    else:
        print("SNMP agent is not disabled.")
        return "Non-Compliant"

# Function to check if only SNMPv3 is enabled
def check_snmpv3_only(shell):
    # Check SNMP sysinfo status
    shell.send('config system snmp sysinfo\n')
    time.sleep(1)
    shell.send('show\n')
    time.sleep(1)
    output_sysinfo = execute_commands(shell, ['show'])[0][1]
    shell.send('end\n')
    time.sleep(1)

    # Check SNMP community settings
    shell.send('config system snmp community\n')
    time.sleep(1)
    shell.send('show\n')
    time.sleep(1)
    output_community = execute_commands(shell, ['show'])[0][1]
    shell.send('end\n')
    time.sleep(1)

    # Check SNMP user settings
    shell.send('config system snmp user\n')
    time.sleep(1)
    shell.send('show\n')
    time.sleep(1)
    output_user = execute_commands(shell, ['show'])[0][1]
    shell.send('end\n')
    time.sleep(1)

    # Check compliance conditions
    sysinfo_compliant = 'set status enable' in output_sysinfo.lower()
    community_compliant = 'config system snmp community' in output_community.lower()
    user_compliant = all(setting in output_user.lower() for setting in [
        'set security-level auth-priv',
        'set auth-proto sha256',
        'set auth-pwd',
        'set priv-proto aes256',
        'set priv-pwd'
    ])

    if sysinfo_compliant and community_compliant and user_compliant:
        print("Only SNMPv3 is enabled.")
        return "Compliant"
    else:
        print("SNMPv3 is not configured correctly.")
        return "Non-Compliant"


# Function to indicate that a manual check is needed for the admin password
def check_admin_password_manual():
    print("Manual check is needed.")
    return "Manual Check Needed"

# Function to check if admin accounts with correct profiles are assigned
def check_admin_profiles(shell):
    # Check accprofile settings for tier_1
    shell.send('config system accprofile\n')
    time.sleep(1)
    shell.send('edit "tier_1"\n')
    time.sleep(1)
    shell.send('show full\n')
    time.sleep(1)
    output_accprofile = execute_commands(shell, ['show full'])[0][1]
    shell.send('end\n')
    time.sleep(1)

    # Check admin settings for support1
    shell.send('config system admin\n')
    time.sleep(1)
    shell.send('edit "support1"\n')
    time.sleep(1)
    shell.send('show full\n')
    time.sleep(1)
    output_admin = execute_commands(shell, ['show full'])[0][1]
    shell.send('end\n')
    time.sleep(1)

    # Check compliance conditions for accprofile
    accprofile_compliant = 'set fwgrp custom' in output_accprofile and 'set address read-write' in output_accprofile

    # Check compliance conditions for admin support1
    admin_compliant = 'set accprofile "tier_1"' in output_admin

    # Both conditions must be compliant to return Compliant
    if accprofile_compliant and admin_compliant:
        print("Admin profiles are correctly assigned.")
        return "Compliant"
    else:
        print("Admin profiles are not correctly assigned.")
        return "Non-Compliant"

# Function to check if the exact 'allowaccess' configuration exists
def check_encrypted_access_channels(shell):
    # Send commands to check system interface settings for port1
    print("Checking encrypted access channels for port1...")
    shell.send('config system interface\n')
    time.sleep(1)
    shell.send('edit port1\n')
    time.sleep(1)
    shell.send('show\n')
    time.sleep(1)
    output_interface = execute_commands(shell, ['show'])[0][1]
    shell.send('end\n')
    time.sleep(1)
    
    # Print the output for debugging purposes
    print(f"Output from port1 configuration:\n{output_interface}")
    
    # Check if the exact 'allowaccess' configuration line exists
    if 'set allowaccess ping https ssh snmp' in output_interface:
        print("Only encrypted access channels are enabled.")
        return "Compliant"
    else:
        print("Unencrypted access channels or different configuration found.")
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
password = 'password@Gat1'
timezone = rf"Asia/Kolkata"
host_name = "New_FGT1"
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

    ntp_compliance = check_ntp_status(shell)
    compliance_results.append({
        "control_objective": "Ensure correct system time is configured through NTP",
        "compliance_status": ntp_compliance
    })
    
    hostname_compliance = check_hostname(shell, host_name)
    compliance_results.append({
        "control_objective": "Ensure hostname is set",
        "compliance_status": hostname_compliance
    })

    firmware_compliance = check_firmware_manual()
    compliance_results.append({
        "control_objective": "Ensure the latest firmware is installed",
        "compliance_status": firmware_compliance
    })

    auto_install_compliance = check_auto_install(shell)
    compliance_results.append({
        "control_objective": "Disable USB Firmware and configuration installation",
        "compliance_status": auto_install_compliance
    })

    tls_compliance = check_tls_static_keys(shell)
    compliance_results.append({
        "control_objective": "Disable static keys for TLS",
        "compliance_status": tls_compliance
    })

    encryption_compliance = check_global_strong_encryption(shell)
    compliance_results.append({
        "control_objective": "Enable Global Strong Encryption",
        "compliance_status": encryption_compliance
    })

    password_policy_compliance = check_password_policy(shell)
    compliance_results.append({
        "control_objective": "Ensure 'Password Policy' is enabled",
        "compliance_status": password_policy_compliance
    })

    admin_lockout_compliance = check_admin_lockout(shell)
    compliance_results.append({
        "control_objective": "Ensure administrator password retries and lockout time are configured",
        "compliance_status": admin_lockout_compliance
    })

    snmp_agent_compliance = check_snmp_agent(shell)
    compliance_results.append({
        "control_objective": "Ensure SNMP agent is disabled",
        "compliance_status": snmp_agent_compliance
    })

    snmpv3_compliance = check_snmpv3_only(shell)
    compliance_results.append({
        "control_objective": "Ensure only SNMPv3 is enabled",
        "compliance_status": snmpv3_compliance
    })

    admin_password_compliance = check_admin_password_manual()
    compliance_results.append({
        "control_objective": "Ensure default 'admin' password is changed",
        "compliance_status": admin_password_compliance
    })

    admin_profiles_compliance = check_admin_profiles(shell)
    compliance_results.append({
        "control_objective": "Ensure admin accounts with different privileges have their correct profiles assigned",
        "compliance_status": admin_profiles_compliance
    })
   
    encrypted_access_compliance = check_encrypted_access_channels(shell)
    compliance_results.append({
        "control_objective": "Ensure only encrypted access channels are enabled",
        "compliance_status": encrypted_access_compliance
    })


    # Write results to CSV
    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    # Close the shell connection
    shell.close()
