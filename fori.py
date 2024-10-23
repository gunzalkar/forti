import paramiko # type: ignore
import re
import csv
import time
import re
def execute_commands(shell, commands):
    results = []
    for command in commands:
        shell.send(command + '\n')
        time.sleep(1)  # Wait for the command to execute
        output = shell.recv(65535).decode('utf-8')
        results.append((command, output))
    return results

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

def check_admin_password_manual():
    print("Manual check is needed.")
    return "Manual Check Needed"

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

def check_antivirus_updates(shell):
    print("Checking Antivirus Definition Push Updates...")

    schedule_command = 'config system autoupdate schedule'
    execute_commands(shell, [schedule_command])

    show_schedule_command = 'show'
    schedule_output = execute_commands(shell, [show_schedule_command])[0][1]

    exit_command = 'end'
    execute_commands(shell, [exit_command])
    tunneling_command = 'config system autoupdate tunneling'
    execute_commands(shell, [tunneling_command])

    show_tunneling_command = 'show'
    tunneling_output = execute_commands(shell, [show_tunneling_command])[0][1]
    execute_commands(shell, [exit_command])

    print("Checking if Antivirus Definition Push Updates are configured...")
    status_pattern = r"\bset status enable\b"

    if re.search(status_pattern, schedule_output, re.IGNORECASE) or re.search(status_pattern, tunneling_output, re.IGNORECASE):
        print("Antivirus Definition Push Updates are configured.")
        return "Compliant (Manual Check Suggested)"
    else:
        print("Antivirus Definition Push Updates are not configured.")
        return "Non-Compliant  (Manual Check Suggested)"

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
def check_auth_lock_settings(shell):
    print("Executing auth-lockout command...")
    enter_command = 'config user setting'
    execute_commands(shell, [enter_command])
    auth_lock_command = 'get | grep -i auth-lock'
    output = execute_commands(shell, [auth_lock_command])[0][1]
    print("****************************************")
    print(output)
    exit_command = 'end'
    execute_commands(shell, [exit_command])
    print("Checking auth-lockout settings...")
    threshold_pattern = r"auth-lockout-threshold\s*:\s*5"
    duration_pattern = r"auth-lockout-duration\s*:\s*300"
    if re.search(threshold_pattern, output) and re.search(duration_pattern, output):
        print("Auth-lockout settings are correct.")
        return "Compliant"
    else:
        print("Auth-lockout settings mismatch: Expected threshold and duration.")
        return "Non-Compliant"
def check_event_logging(shell):
    print("Executing event logging command...")

    # Step 1: Enter 'config log eventfilter'
    enter_command = 'config log eventfilter'
    execute_commands(shell, [enter_command])

    # Step 2: Execute 'get | grep -i event'
    event_command = 'get | grep -i event'
    output = execute_commands(shell, [event_command])[0][1]

    # Step 3: Exit the config mode using 'end'
    exit_command = 'end'
    execute_commands(shell, [exit_command])

    print("Checking event logging settings...")

    # Use regex to check for the word 'enable' with varying spaces
    event_logging_pattern = r"\benable\b"

    # Check if the word 'enable' exists in the output
    if re.search(event_logging_pattern, output, re.IGNORECASE):
        print("Event logging is enabled.")
        return "Compliant"
    else:
        print("Event logging is not enabled.")
        return "Non-Compliant"
def check_fortianalyzer_encryption(shell):
    print("Executing FortiAnalyzer encryption command...")
    enter_command = 'config log fortianalyzer setting'
    execute_commands(shell, [enter_command])
    enc_command = 'get | grep -i enc'
    output = execute_commands(shell, [enc_command])[0][1]
    exit_command = 'end'
    execute_commands(shell, [exit_command])
    print("Checking FortiAnalyzer encryption settings...")
    encryption_pattern = r"\bhigh\b"
    if re.search(encryption_pattern, output, re.IGNORECASE):
        print("FortiAnalyzer encryption is set to high.")
        return "Compliant"
    else:
        print("FortiAnalyzer encryption is not set to high.")
        return "Non-Compliant"
def check_centralized_logging(shell):
    print("Checking Centralized Logging and Reporting...")

    
    log_setting_command = 'get log setting'
    output_log_setting = execute_commands(shell, [log_setting_command])[0][1]
    print("Log Setting Output:")
    print(output_log_setting)

    
    if re.search(r"\bdisable\b", output_log_setting, re.IGNORECASE):
        print("Log setting contains 'disable'.")
        return "Non-Compliant (Manual Check Suggested)"
    else:
        print("Log setting does not contain 'disable'.")

   
    log_syslogd_command = 'get log syslogd setting'
    output_log_syslogd = execute_commands(shell, [log_syslogd_command])[0][1]
    print("Syslogd Setting Output:")
    print(output_log_syslogd)

    
    if re.search(r"status\s*:\s*enable", output_log_syslogd, re.IGNORECASE):
        print("Syslogd status is enabled.")
    else:
        print("Syslogd status is not enabled.")
        return "Non-Compliant (Manual Check Suggested)"

    log_fortianalyzer_command = 'get log fortianalyzer setting'
    output_log_fortianalyzer = execute_commands(shell, [log_fortianalyzer_command])[0][1]
    print("FortiAnalyzer Setting Output:")
    print(output_log_fortianalyzer)

    if re.search(r"status\s*:\s*enable", output_log_fortianalyzer, re.IGNORECASE):
        print("FortiAnalyzer status is enabled.")
    else:
        print("FortiAnalyzer status is not enabled.")
        return "Non-Compliant (Manual Check Suggested)"

    # If all conditions are met, the check is compliant
    print("Centralized Logging and Reporting is compliant.")
    return "Compliant (Manual Check Suggested)"


def check_dns_filter_policy(shell):
    print("Manual check needed:DNS Filter.")
    
    # Indicate that a manual check is required
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

    antivirus_updates_compliance = check_antivirus_updates(shell)
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

    auth_lock_compliance = check_auth_lock_settings(shell)
    compliance_results.append({
        "control_objective": "Configuring the maximum login attempts and lockout period",
        "compliance_status": auth_lock_compliance
    })


    event_logging_compliance = check_event_logging(shell)
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

    dns_check_policy = check_dns_filter_policy(shell)
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
