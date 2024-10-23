import paramiko
import re
import csv
import time
import re

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
    print("****************************************")
    print(output)
    
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
    
    # Check if the exact 'allowaccess' configuration line exists
    if 'set allowaccess ping https ssh snmp' in output_interface:
        print("Only encrypted access channels are enabled.")
        return "Compliant"
    else:
        print("Unencrypted access channels or different configuration found.")
        return "Non-Compliant"

# Function to check High Availability configuration
def check_ha_configuration(shell):
    # Send commands to check HA settings
    print("Checking High Availability configuration...")
    shell.send('config system ha\n')
    time.sleep(1)
    shell.send('show\n')
    time.sleep(1)
    output_ha = execute_commands(shell, ['show'])[0][1]
    shell.send('end\n')
    time.sleep(1)
    
    
    # Check if 'set mode a-p' exists in the HA configuration
    if 'set mode a-p' in output_ha:
        print("High Availability is configured in Active-Passive mode.")
        return "Compliant"
    else:
        print("High Availability is not properly configured.")
        return "Non-Compliant"

# Function to check if Monitor Interfaces for HA devices is enabled
def check_ha_monitor_interfaces(shell):
    # Send commands to check HA settings
    print("Checking Monitor Interfaces in High Availability configuration...")
    shell.send('config system ha\n')
    time.sleep(1)
    shell.send('show\n')
    time.sleep(1)
    output_ha_monitor = execute_commands(shell, ['show'])[0][1]
    shell.send('end\n')
    time.sleep(1)
    
    # Check if 'set monitor' exists in the HA configuration
    if 'set monitor' in output_ha_monitor:
        print("Monitor Interfaces for HA devices is enabled.")
        return "Compliant"
    else:
        print("Monitor Interfaces for HA devices is not enabled.")
        return "Non-Compliant"

# Function to check if HA Reserved Management Interface is configured
def check_ha_mgmt_interface(shell):
    # Send commands to check HA settings
    print("Checking HA Reserved Management Interface configuration...")
    shell.send('config system ha\n')
    time.sleep(1)
    shell.send('show\n')
    time.sleep(1)
    output_ha_mgmt = execute_commands(shell, ['show'])[0][1]
    shell.send('end\n')
    time.sleep(1)

    if 'config ha-mgmt-interfaces' in output_ha_mgmt:
        print("HA Reserved Management Interface is configured.")
        return "Compliant"
    else:
        print("HA Reserved Management Interface is not configured.")
        return "Non-Compliant"

def check_unused_policies():
    print("Manual check is needed for reviewing unused policies.")
    return "Manual Check Needed"

def check_unique_policy_names():
    print("Manual check is needed to ensure policies are uniquely named.")
    return "Manual Check Needed"

def check_unused_firewall_policies():
    print("Manual check is needed to ensure there are no unused firewall policies.")
    return "Manual Check Needed"

def check_botnet_connections():
    print("Manual check is needed to detect botnet connections.")
    return "Manual Check Needed"

# Function to check Antivirus Definition Push Updates configuration
def check_antivirus_definition_updates(shell):
    print("Executing Antivirus Definition Push Updates command...")
    
    # Commands to execute
    commands = [
        'end',
        'config system autoupdate',
        'show'
        'end',
        'config system autoupdate push-update',
        'show',
        'end',
        'config system autoupdate schedule',
        'show',
        'end',
        'config system autoupdate tunneling',
        'show',
        'end'
    ]
    
    # Execute commands
    outputs = execute_commands(shell, commands)
    print("******************************************************")
    print(outputs)
    # Check for 'set status enable' in the output
    for output in outputs:
        if 'set status enable' in output[1].lower():
            print("Antivirus Definition Push Updates are configured.")
            return "Compliant"
    
    print("Antivirus Definition Push Updates are not configured.")
    return "Non-Compliant"

def check_antivirus_security_profile():
    print("Manual check needed: Ensure Antivirus Security Profile is applied to Policies.")
    return "Manual check needed"
def check_botnet_cnc_domain_blocking():
    print("Manual check needed: Ensure Botnet C&C Domain Blocking DNS Filter is enabled.")
    return "Manual check needed"
def check_compromised_host_quarantine():
    print("Manual check needed: Ensure Compromised Host Quarantine is enabled.")
    return "Manual check needed"
def check_security_fabric():
    print("Manual check needed: Ensure Security Fabric is configured.")
    return "Manual check needed"
def check_trusted_signed_certificate():
    print("Manual check needed: Apply a Trusted Signed Certificate for VPN Portal.")
    return "Manual check needed"
    
def check_auth_lockout_settings(shell):
    print("Executing authentication lockout settings command...")
    auth_lockout_command = 'end\nconfig user setting\nget | grep -i auth-lock\nend'
    output = execute_commands(shell, [auth_lockout_command])[0][1]
    print("Checking authentication lockout settings...")
    required_settings = {
        'auth-lockout-threshold': '5',
        'auth-lockout-duration': '300'
    }
    print("*"*50)
    print(output)

    for key, value in required_settings.items():
        pattern = fr"{key}:\s*{value}"
        if not re.search(pattern, output):
            print(f"Authentication lockout setting mismatch: Expected {key} to be {value}")
            return "Non-Compliant"
    
    print("Authentication lockout settings are correct.")
    return "Compliant"

def check_event_logging_settings(shell):
    print("Executing event logging settings command...")
    event_logging_command = 'end\nconfig log eventfilter\nget | grep -i event\nend'
    output = execute_commands(shell, [event_logging_command])[0][1]
    
    print("Checking event logging settings...")
    if 'enable' in output.lower():
        print("Event logging is enabled.")
        return "Compliant"
    else:
        print("Event logging is not enabled.")
        return "Non-Compliant"

def check_fortianalyzer_encryption(shell):
    print("Executing FortiAnalyzer/FortiManager log encryption command...")
    log_encryption_command = 'end\nconfig log fortianalyzer setting\nget | grep -i enc\nend'
    output = execute_commands(shell, [log_encryption_command])[0][1]
    
    print("Checking FortiAnalyzer/FortiManager log encryption settings...")
    if 'low' in output.lower():
        print("Log encryption is set to high.")
        return "Compliant"
    else:
        print("Log encryption is not set to high.")
        return "Non-Compliant"

def check_centralized_logging(shell):
    # Check first command: get log setting
    print("Executing 'get log setting' command...")
    log_setting_command = 'get log setting'
    log_setting_output = execute_commands(shell, [log_setting_command])[0][1]
    
    print("****************************************")
    print(log_setting_output)

    # Check if 'disable' exists in the output (case-insensitive)
    if re.search(r'\bdisable\b', log_setting_output, re.IGNORECASE):
        print("Log setting contains 'disable'. This is Non-Compliant.")
        return "Non-Compliant (Manual Check Needed)"

    # Check second command: get log syslogd setting
    print("Executing 'get log syslogd setting' command...")
    syslogd_setting_command = 'get log syslogd setting'
    syslogd_setting_output = execute_commands(shell, [syslogd_setting_command])[0][1]
    
    print("****************************************")
    print(syslogd_setting_output)

    # Check if 'status' is 'enable' (ignore spaces)
    if not re.search(r'status\s*:\s*enable', syslogd_setting_output, re.IGNORECASE):
        print("Syslogd setting is not enabled. This is Non-Compliant.")
        return "Non-Compliant"

    # Check third command: get log fortianalyzer setting
    print("Executing 'get log fortianalyzer setting' command...")
    fortianalyzer_setting_command = 'get log fortianalyzer setting'
    fortianalyzer_setting_output = execute_commands(shell, [fortianalyzer_setting_command])[0][1]
    
    print("****************************************")
    print(fortianalyzer_setting_output)

    # Check if 'status' is 'enable' (ignore spaces)
    if not re.search(r'status\s*:\s*enable', fortianalyzer_setting_output, re.IGNORECASE):
        print("FortiAnalyzer setting is not enabled. This is Non-Compliant.")
        return "Non-Compliant"

    # If all checks are compliant
    print("All log settings are Compliant.")
    return "Compliant (Manual Check Suggested)"

def check_dns_filter_policy(shell):
    print("Manual check needed:DNS Filter.")
    return "Manual check needed"

def check_ips_security_profile(shell):
    print("Manual check needed to ensure that IPS Security Profile is applied to policies.")
    
    # Indicate that a manual check is required
    return "Manual check needed"

def check_trusted_hosts(shell):
    print("Manual check needed to ensure that all login accounts have specific trusted hosts enabled.")
    
    # Indicate that a manual check is required
    return "Manual check needed"

def check_service_all(shell):
    print("Manual check needed to ensure that policies do not use 'ALL' as Service.")

    # Indicate that a manual check is required
    return "Manual check needed"

def check_idle_timeout(shell):
    print("Manual check needed to ensure that idle timeout time is configured.")

    # Indicate that a manual check is required
    return "Manual check needed"

def check_admin_profiles(shell):
    print("Manual check needed to ensure that admin accounts with different privileges have their correct profiles assigned.")

    # Indicate that a manual check is required
    return "Manual check needed"

def check_dns_filter_logging(shell):
    print("Manual check needed to ensure that DNS Filter logs all DNS queries and responses.")

    # Indicate that a manual check is required
    return "Manual check needed"

def write_to_csv(compliance_results):
    with open('compliance_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Sr No.", "Control Objective", "Compliance Status"])
        for index, result in enumerate(compliance_results, start=1):
            writer.writerow([index, result['control_objective'], result['compliance_status']])

hostname = '192.168.1.1'
username = 'admin'
password = 'password@Gat1'
timezone = rf"Asia/Kolkata"
host_name = "New_FGT1"
shell = connect_to_fortigate(hostname, username, password)

if shell:
    compliance_results = []

    dns_compliance = check_dns_settings(shell)
    compliance_results.append({
        "control_objective": "Ensure DNS server is configured",
        "compliance_status": dns_compliance
    })

    intrazone_compliance = check_intrazone_traffic(shell)
    compliance_results.append({
        "control_objective": "Ensure intra-zone traffic is not always allowed",
        "compliance_status": intrazone_compliance
    })

    pre_login_banner_compliance = check_pre_login_banner(shell)
    compliance_results.append({
        "control_objective": "Ensure 'Pre-Login Banner' is set",
        "compliance_status": pre_login_banner_compliance
    })

    post_login_banner_compliance = check_post_login_banner(shell)
    compliance_results.append({
        "control_objective": "Ensure 'Post-Login Banner' is set",
        "compliance_status": post_login_banner_compliance
    })

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

    ha_compliance = check_ha_configuration(shell)
    compliance_results.append({
        "control_objective": "Ensure High Availability Configuration",
        "compliance_status": ha_compliance
    })

    ha_monitor_compliance = check_ha_monitor_interfaces(shell)
    compliance_results.append({
        "control_objective": "Ensure 'Monitor Interfaces' for High Availability Devices is Enabled",
        "compliance_status": ha_monitor_compliance
    })

    ha_mgmt_compliance = check_ha_mgmt_interface(shell)
    compliance_results.append({
        "control_objective": "Ensure HA Reserved Management Interface is Configured",
        "compliance_status": ha_mgmt_compliance
    })

    unused_policies_compliance = check_unused_policies()
    compliance_results.append({
        "control_objective": "Ensure that unused policies are reviewed regularly",
        "compliance_status": unused_policies_compliance
    })

    unique_policy_names_compliance = check_unique_policy_names()
    compliance_results.append({
        "control_objective": "Ensure Policies are Uniquely Named",
        "compliance_status": unique_policy_names_compliance
    })

    unused_firewall_policies_compliance = check_unused_firewall_policies()
    compliance_results.append({
        "control_objective": "Ensure that there are no firewall policies that are unused",
        "compliance_status": unused_firewall_policies_compliance
    })

    botnet_connections_compliance = check_botnet_connections()
    compliance_results.append({
        "control_objective": "Detect Botnet Connections",
        "compliance_status": botnet_connections_compliance
    })

    antivirus_updates_compliance = check_antivirus_definition_updates(shell)
    compliance_results.append({
        "control_objective": "Ensure Antivirus Definition Push Updates are Configured",
        "compliance_status": antivirus_updates_compliance
    })

    antivirus_profile_compliance = check_antivirus_security_profile()
    compliance_results.append({
        "control_objective": "Apply Antivirus Security Profile to Policies",
        "compliance_status": antivirus_profile_compliance
    })

    botnet_cnc_domain_blocking_compliance = check_botnet_cnc_domain_blocking()
    compliance_results.append({
        "control_objective": "Enable Botnet C&C Domain Blocking DNS Filter",
        "compliance_status": botnet_cnc_domain_blocking_compliance
    })

    compromised_host_quarantine_compliance = check_compromised_host_quarantine()
    compliance_results.append({
        "control_objective": "Enable Compromised Host Quarantine",
        "compliance_status": compromised_host_quarantine_compliance
    })

    security_fabric_compliance = check_security_fabric()
    compliance_results.append({
        "control_objective": "Ensure Security Fabric is Configured",
        "compliance_status": security_fabric_compliance
    })

    trusted_signed_certificate_compliance = check_trusted_signed_certificate()
    compliance_results.append({
        "control_objective": "Apply a Trusted Signed Certificate for VPN Portal",
        "compliance_status": trusted_signed_certificate_compliance
    })

    auth_lockout_compliance = check_auth_lockout_settings(shell)
    compliance_results.append({
        "control_objective": "Configuring the maximum login attempts and lockout period",
        "compliance_status": auth_lockout_compliance
    })

    event_logging_compliance = check_event_logging_settings(shell)
    compliance_results.append({
        "control_objective": "Enable Event Logging",
        "compliance_status": event_logging_compliance
    })

    fortianalyzer_encryption_compliance = check_fortianalyzer_encryption(shell)
    compliance_results.append({
        "control_objective": "Encrypt Log Transmission to FortiAnalyzer / FortiManager",
        "compliance_status": fortianalyzer_encryption_compliance
    })

    centralized_logging_compliance = check_centralized_logging(shell)
    compliance_results.append({
        "control_objective": "Centralized Logging and Reporting",
        "compliance_status": centralized_logging_compliance
    })

    dns_check_policy = check_dns_filter_policy
    compliance_results.append({
        "control_objective": "Apply DNS Filter Security Profile to Policies",
        "compliance_status": dns_check_policy
    })

    ips_security_profile_compliance = check_ips_security_profile(shell)
    compliance_results.append({
        "control_objective": "Apply IPS Security Profile to Policies",
        "compliance_status": ips_security_profile_compliance
    })

    trusted_hosts_compliance = check_trusted_hosts(shell)
    compliance_results.append({
        "control_objective": "Ensure all login accounts have specific trusted hosts enabled",
        "compliance_status": trusted_hosts_compliance
    })

    service_all_compliance = check_service_all(shell)
    compliance_results.append({
        "control_objective": "Ensure that policies do not use 'ALL' as Service - ALL as Service",
        "compliance_status": service_all_compliance
    })

    idle_timeout_compliance = check_idle_timeout(shell)
    compliance_results.append({
        "control_objective": "Ensure idle timeout time is configured",
        "compliance_status": idle_timeout_compliance
    })

    admin_profiles_compliance = check_admin_profiles(shell)
    compliance_results.append({
        "control_objective": "Ensure admin accounts with different privileges have their correct profiles assigned",
        "compliance_status": admin_profiles_compliance
    })

    dns_filter_logging_compliance = check_dns_filter_logging(shell)
    compliance_results.append({
        "control_objective": "Ensure DNS Filter logs all DNS queries and responses",
        "compliance_status": dns_filter_logging_compliance
    })

    write_to_csv(compliance_results)
    print("Compliance report has been written to 'compliance_report.csv'.")

    shell.close()
