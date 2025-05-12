import platform
import subprocess
import socket
import os 
import re
import paramiko

def ping_ip(ip_address: str) -> dict:
    """
    Pings a given IP address and returns detailed metrics including reachability,
    average RTT (Round-Trip Time), and packet loss percentage.

    Args:
        ip_address: The IP address to ping (as a string).

    Returns:
        A dictionary with keys:
        - 'is_reachable' (bool): True if the host is reachable, False otherwise.
        - 'rtt_avg_ms' (float | None): Average RTT in milliseconds, or None if not determinable.
        - 'packet_loss_percent' (float | None): Packet loss percentage, or None if not determinable.
        - 'raw_output' (str): Raw output from the ping command for debugging.
    """
    system = platform.system().lower()
    count_param = '-n' if system == 'windows' else '-c'
    count_value = '4' 
    
    command = ['ping', count_param, count_value, str(ip_address)]
    if system == 'windows':
        command.insert(3, '-w') 
        command.insert(4, '1000') 
    else: 
        command.insert(3, '-W') 
        command.insert(4, '1')   

    process = None
    raw_output = ""
    rtt_avg_ms = None
    packet_loss_percent = None
    is_reachable = False

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        stdout, stderr = process.communicate(timeout=10) 
        raw_output = stdout + stderr

        if process.returncode == 0:
            is_reachable = True
            if system == 'windows':
                match_rtt = re.search(r"Average = (\d+)ms", raw_output)
                if match_rtt: rtt_avg_ms = float(match_rtt.group(1))
                match_loss = re.search(r"Lost = \d+ \((\d+)% loss\)", raw_output)
                if match_loss: packet_loss_percent = float(match_loss.group(1))
                elif "Lost = 0 (0% loss)" in raw_output : packet_loss_percent = 0.0
            else: 
                match_rtt = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", raw_output)
                if match_rtt: rtt_avg_ms = float(match_rtt.group(1))
                match_loss = re.search(r"(\d+)% packet loss", raw_output)
                if match_loss: packet_loss_percent = float(match_loss.group(1))
        else:
            if system == 'windows':
                match_loss = re.search(r"Lost = \d+ \((\d+)% loss\)", raw_output)
                if match_loss: packet_loss_percent = float(match_loss.group(1))
                elif "Sent = "+count_value+", Received = 0" in raw_output: packet_loss_percent = 100.0
            else: 
                match_loss = re.search(r"(\d+)% packet loss", raw_output)
                if match_loss: packet_loss_percent = float(match_loss.group(1))
                elif "0 received" in raw_output or "0 packets received" in raw_output : packet_loss_percent = 100.0
    except subprocess.TimeoutExpired:
        raw_output = "Ping command timed out."
        is_reachable = False
        packet_loss_percent = 100.0 
        if process:
            process.kill()
            stdout, stderr = process.communicate()
            raw_output += "\n" + stdout + stderr
    except FileNotFoundError:
        raw_output = "Error: 'ping' command not found."
        is_reachable = False
    except Exception as e:
        raw_output = f"An error occurred while pinging: {e}"
        is_reachable = False
    
    return {
        'is_reachable': is_reachable, 'rtt_avg_ms': rtt_avg_ms,
        'packet_loss_percent': packet_loss_percent, 'raw_output': raw_output.strip()
    }

def check_tcp_port(ip_address: str, port: int, timeout: float = 1.0) -> bool:
    """Checks if a specific TCP port is open on a given IP address."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_address, port))
        return result == 0
    except (socket.timeout, socket.gaierror, OverflowError, Exception):
        return False
    finally:
        if sock: sock.close()

def _execute_single_ssh_command(ssh_client, command: str, timeout: int = 10) -> tuple[str, str, int]:
    """Helper to execute a single command on an established SSH client."""
    stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
    stdout_output = stdout.read().decode(errors='ignore').strip()
    stderr_output = stderr.read().decode(errors='ignore').strip()
    exit_status = stdout.channel.recv_exit_status()
    return stdout_output, stderr_output, exit_status

def execute_ssh_command(hostname: str, port: int, username: str, password: str, command: str, timeout: int = 10) -> tuple[str | None, str | None, bool]:
    """Executes a command on a remote host via SSH using username/password authentication."""
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname=hostname, port=port, username=username, password=password,
            timeout=timeout, allow_agent=False, look_for_keys=False
        )
        stdout_output, stderr_output, exit_status = _execute_single_ssh_command(ssh_client, command, timeout)
        return stdout_output, stderr_output, exit_status == 0
    except paramiko.AuthenticationException:
        return None, "Authentication failed.", False
    except paramiko.SSHException as ssh_ex:
        return None, f"SSH connection error: {ssh_ex}", False
    except socket.timeout:
        return None, "Connection timed out.", False
    except Exception as e:
        return None, f"Unexpected error: {e}", False
    finally:
        if ssh_client: ssh_client.close()

def get_ssh_device_info(hostname: str, port: int, username: str, password: str, timeout: int = 10) -> dict:
    """
    Retrieves basic device information (OS, Uptime) from a remote host via SSH.

    Args:
        hostname, port, username, password: SSH connection details.
        timeout: Connection and command execution timeout.

    Returns:
        A dictionary containing 'os_info', 'uptime_info', 'error', 'success_flag'.
        'os_info' and 'uptime_info' will be None if retrieval fails.
        'error' will contain an error message on failure.
    """
    ssh_client = None
    result = {'os_info': None, 'uptime_info': None, 'error': None, 'success_flag': False}
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname=hostname, port=port, username=username, password=password,
            timeout=timeout, allow_agent=False, look_for_keys=False
        )

        # Get OS Information
        os_stdout, os_stderr, os_exit_status = _execute_single_ssh_command(ssh_client, "uname -a", timeout)
        if os_exit_status == 0:
            result['os_info'] = os_stdout
        else:
            result['error'] = f"Failed to get OS info: {os_stderr or os_stdout}"
            # Continue to try getting uptime even if uname fails

        # Get Uptime Information
        uptime_stdout, uptime_stderr, uptime_exit_status = _execute_single_ssh_command(ssh_client, "uptime", timeout)
        if uptime_exit_status == 0:
            result['uptime_info'] = uptime_stdout
        else:
            # Append to error if already set
            uptime_err_msg = f"Failed to get uptime: {uptime_stderr or uptime_stdout}"
            result['error'] = f"{result['error']}; {uptime_err_msg}" if result['error'] else uptime_err_msg
        
        # Consider successful if at least one piece of info was retrieved without connection error
        if result['os_info'] or result['uptime_info']:
            result['success_flag'] = True # Even if one command failed but connection was okay
        
        if os_exit_status != 0 and uptime_exit_status != 0 and not result['error']: # If both failed but no specific error captured
            result['error'] = "Both OS info and uptime commands failed."


    except paramiko.AuthenticationException:
        result['error'] = "Authentication failed."
    except paramiko.SSHException as ssh_ex:
        result['error'] = f"SSH connection error: {ssh_ex}"
    except socket.timeout:
        result['error'] = "Connection timed out."
    except Exception as e:
        result['error'] = f"Unexpected error: {e}"
    finally:
        if ssh_client: ssh_client.close()
    
    # If there was a connection-level error, ensure success_flag is False
    if result['error'] and not (result['os_info'] or result['uptime_info']):
        result['success_flag'] = False
        
    return result


if __name__ == '__main__':
    print("--- Testing Enhanced Ping ---")
    print(f"Pinging 8.8.8.8: {ping_ip('8.8.8.8')}")
    
    print("\n--- Testing Port Check ---")
    print(f"Checking port 443 on google.com: {'Open' if check_tcp_port('google.com', 443) else 'Closed/Filtered'}")

    print("\n--- SSH Device Info Example ---")

    
    # Replace with actual SSH server details
    # ssh_host_test = "ssh host ip"
    # ssh_user_test = "username"
    # ssh_pass_test = "password"
    
    # if ssh_host_test != "_ssh host ip":
    #     info = get_ssh_device_info(ssh_host_test, 22, ssh_user_test, ssh_pass_test)
    #     if info['success_flag']:         print(f"OS Info from {ssh_host_test}: {info['os_info']}")                    print(f"Uptime from {ssh_host_test}: {info['uptime_info']}")
    #     else:                            print(f"Failed to get device info from {ssh_host_test}: {info['error']}")
    # else:                                print("SSH Device Info test skipped (placeholder credentials).")




    
    print("SSH Device Info test illustrative. Update placeholders in __main__ to test.")
