import subprocess
import re
import os
import shutil
import configparser
import pyfiglet
import colorama

colorama.init(autoreset=True)

DEFAULT_PORT = 2222
CONFIG_FILE_PATH = '/etc/ssh/sshd_config'
DEFAULT_BACKUP_DIR = '/var/lib/s3h'


def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()
    
def write_file(file_path, file_content):
    with open(file_path, 'w') as w:
        w.write(file_content)


def ask_permission(message, default_input):
    valid_inputs = {'yes', 'no', 'y', 'n'}

    while True:
        user_input = input(message).lower().strip()
        if user_input in valid_inputs:
            return user_input == 'yes' or user_input == 'y'
        if user_input == '':
            return default_input
        else:
            print("Invalid input.")

def check_sudo():
    return 'SUDO_UID' in os.environ


def hello_message():
    print('Welcome to S3H (Super Secure Shell)!')
    styled_text = pyfiglet.figlet_format('S3H', font='slant')
    print(colorama.Fore.GREEN + styled_text)


reserved_ports = [20, 21, 23, 25, 53, 80, 110, 143, 443, 3306]
def get_new_port():
    while True:
        port = input("Choose port to run SSH server on: [2222]: ")
        if port == "":
            port = 2222
        else:
            try:
                port = int(port)
                if port < 1 or port > 65535:
                    raise ValueError("bounds_error")

                if port in reserved_ports:
                    raise ValueError('another_service_error')

                if port == 22:
                    confirm = ask_permission("Port 22 is the default SSH port and might not be safe. Are you sure you want to use it? (y/n) [n]: ", False)
                    if confirm:
                        return port
                    continue

                return port
            except ValueError as e:
                if "invalid literal" in str(e):
                    print("Invalid port number. Please enter a valid integer port number.")
                if "bounds_error" in str(e):
                    print('Port number must be between 1 and 65535')
                if "another_service_error" in str(e):
                    print("This port might be used by another service. Using it may cause problems.")



def update_port(port):
    config_content = read_file(CONFIG_FILE_PATH)
    config_content = re.sub(r'^\s*#?\s*Port\s+\d+', f'Port {port}', config_content, flags=re.MULTILINE)
    write_file(CONFIG_FILE_PATH, config_content)
    print(f"Port in SSH config file set to {port}")


def set_permit_root_login(ask):
    if ask:
        permit_root_login = ask_permission("Do you want to permit root login? (y/n) [n]:", False)
    else:
        permit_root_login = False
       
    config_content = read_file(CONFIG_FILE_PATH)

    if permit_root_login:
        config_content = re.sub(r'^\s*#?\s*PermitRootLogin\s+\w+', 'PermitRootLogin yes', config_content, flags=re.MULTILINE)
    else:
        config_content = re.sub(r'^\s*#?\s*PermitRootLogin\s+\w+', 'PermitRootLogin no', config_content, flags=re.MULTILINE)

    write_file(CONFIG_FILE_PATH, config_content)
    print(f"PermitRootLogin in SSH config file set to {'yes' if permit_root_login else 'no'}")


def set_permit_password_login(ask):
    if ask:
        permit_password_login = ask_permission("Do you want to permit password login? (y/n) [n]:", False)
    else:
        permit_password_login = False

    config_content = read_file(CONFIG_FILE_PATH)

    if permit_password_login:
        config_content = re.sub(r'^\s*#?\s*PasswordAuthentication\s+\w+', 'PasswordAuthentication yes', config_content, flags=re.MULTILINE)
    else:
        config_content = re.sub(r'^\s*#?\s*PasswordAuthentication\s+\w+', 'PasswordAuthentication no', config_content, flags=re.MULTILINE)

   # empty passwords always no
    config_content = re.sub(r'^\s*#?\s*PermitEmptyPasswords\s+\w+', 'PermitEmptyPasswords no', config_content, flags=re.MULTILINE)

    write_file(CONFIG_FILE_PATH, config_content)
    print(f"PasswordAuthentication in SSH config file set to {'yes' if permit_password_login else 'no'}")
    if not permit_password_login:
        print('Set up public key authentication to gain access to server!')


def create_backup(source_file=CONFIG_FILE_PATH, backup_dir=DEFAULT_BACKUP_DIR):
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
  
    file_name = 'sshd_config_backup'
    backup_file = os.path.join(backup_dir, file_name)
    shutil.copy(source_file, backup_file)
    print(f"Config backup created at {backup_file}")
    return backup_file


def restore_from_backup(backup_file='/var/lib/s3h/sshd_config_backup', destination_file='/etc/ssh/sshd_config'):
    if not os.path.exists('/var/lib/s3h/'):
        print('No backup directory found')
        return False
  
    if not os.path.isdir('/var/lib/s3h'):
        print('Backup path is not a directory')
        return False

    files = os.listdir('/var/lib/s3h')

    if files:
        try:
            shutil.copy(backup_file, destination_file)
            print(f'Successfully restored from {backup_file}')
            return True
        except Exception as e:
            print(f"Error restoring from backup: {e}")
            return False
    else:
        print('No files found in backup directory')
        return False
  

def set_banner(ask):
    if ask:
        allow_banner = ask_permission("Do you want to set banner text? (y/n) [y]: ", True)
    else:
        allow_banner = False
   
    config_content = read_file(CONFIG_FILE_PATH)
    config_content = re.sub(r'^\s*#?\s*Banner\s+\S+', 'Banner /etc/issue.net', config_content, flags=re.MULTILINE)
    write_file(CONFIG_FILE_PATH, config_content)

    if not allow_banner:
        write_file('/etc/issue.net', 'This server is protected by S3H.' + '\n')
        print('Setting banner text to default...')
    else:
        try:
            subprocess.run(['nano', '/etc/issue.net'])           
            print('Banner text set successfully')
        except Exception as e:
            print(f'Error setting banner text: {e}')


def set_timeouts():
    config_content = read_file(CONFIG_FILE_PATH)
    print('Setting client alive intervals...')
    config_content = re.sub(r'^\s*#?\s*ClientAliveInterval\s+\d+', 'ClientAliveInterval 300', config_content, flags=re.MULTILINE)
    config_content = re.sub(r'^\s*#?\s*ClientAliveCountMax\s+\d+', 'ClientAliveCountMax 3', config_content, flags=re.MULTILINE)
    config_content = re.sub(r'^\s*#?\s*TCPKeepAlive\s+\w+', 'TCPKeepAlive yes', config_content, flags=re.MULTILINE)
    write_file(CONFIG_FILE_PATH, config_content)


def set_cryptography():
    print('Setting optimal cryptographic algorithms...')
    optimal_ciphers = [
       "Ciphers aes128-ctr,aes192-ctr,aes256-ctr",
       "HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss",
       "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256",
       "MACs hmac-sha2-256,hmac-sha2-512"
   ]

    config_content = read_file(CONFIG_FILE_PATH)
    present_ciphers = [cipher for cipher in optimal_ciphers if cipher in config_content]

    if len(present_ciphers) == len(optimal_ciphers):
        print("Optimal cryptographic algorithms are already set.")
        return

    with open(CONFIG_FILE_PATH, 'a') as file:
        file.write('\n')
        for cipher in optimal_ciphers:
            if cipher not in present_ciphers:
                file.write(cipher + '\n')

    print("Optimal cryptographic algorithms added successfully.")


def set_logging():
    config_content = read_file(CONFIG_FILE_PATH)
    print('Setting log level to verbose...')
    config_content = re.sub(r'^\s*#?\s*LogLevel\s+\w+', 'LogLevel VERBOSE', config_content, flags=re.MULTILINE)
    write_file(CONFIG_FILE_PATH, config_content)


def set_whitelist():
    valid_inputs = {'yes', 'no', 'y', 'n'}
    default_input = True
    allow_whitelist = True

    while True:
        config_content = read_file(CONFIG_FILE_PATH)
        allow_users_line = [line.strip() for line in config_content.split('\n') if line.strip().startswith('AllowUsers') and not line.strip().startswith('#')]

        if allow_users_line:
            change_whitelist_input = input("Whitelist is detected in the configuration file. Do you want to change it? (y/n) [y]: ").lower().strip()
            if change_whitelist_input in valid_inputs:
                allow_whitelist = change_whitelist_input == 'yes' or change_whitelist_input == 'y'
                if not allow_whitelist:
                    print('Skipping whitelist creation...')
                    return
                break
            elif not change_whitelist_input:
                allow_whitelist = default_input
                break
            else:
                print("Invalid input. Please enter 'yes' or 'no'.")
                continue
        else:
            allow_whitelist = True
            break

    if allow_whitelist:
        while True:
            users_input = input("Enter a space-separated list of usernames: ").strip()
            users = [user.strip() for user in users_input.split(' ')]
            invalid_users = [user for user in users if not user.isalnum()]

            if invalid_users:
                print(f"Error: Invalid usernames detected: {', '.join(invalid_users)}")
                retry_input = input("Do you want to retry entering usernames? (y/n) [y]: ").lower().strip()
                if retry_input not in valid_inputs:
                    print("Invalid input.")
                    continue
                elif retry_input == 'yes' or retry_input == 'y':
                    continue
                else:
                    print("Skipping whitelist creation...")
                    return
            else:
                break
      
        config_content = re.sub(r'^\s*#?\s*AllowUsers\s+.*', f'AllowUsers {" ".join(users)}', config_content, flags=re.MULTILINE)
        write_file(CONFIG_FILE_PATH, config_content)
        print("Whitelisted users added successfully.")
    else:
        print('Skipping whitelist creation...')
  

def set_up_tarpit(ask):
    if os.path.exists("/usr/local/bin/endlessh") and os.path.exists("/etc/systemd/system/endlessh.service"):
        print("Endlessh is already installed and set up. Skipping tarpit setup. Run 'sudo systemctl stop endlessh && sudo rm /usr/local/bin/endlessh && sudo rm /etc/systemd/system/endlessh.service' to reinstall")
        return

    if (ask):
        allow_tarpit = ask_permission('Do you want to set up Endlessh? (y/n) [y]: ', True)
    else:
        allow_tarpit = True

    if allow_tarpit:
        while True:
            tarpit_port = input("Enter the port to run Endlessh on (22 is recommended) [22]: ").strip() or '22'
            try:
                tarpit_port = int(tarpit_port)
                if tarpit_port < 1 or tarpit_port > 65535:
                    raise ValueError
                break
            except ValueError:
                print("Invalid port number. Please enter a valid integer port number.")

        subprocess.run(['sudo', 'systemctl', 'stop', 'ssh'])
        if not os.path.exists("endlessh"):
            os.system("git clone https://github.com/skeeto/endlessh.git")
        os.chdir("endlessh")

        if not os.path.exists("/usr/local/bin/endlessh"):
            subprocess.run(["make"])
            os.system('sudo mv endlessh /usr/local/bin/')

        if not os.path.exists("/etc/systemd/system/endlessh.service"):
            os.system('sudo cp util/endlessh.service /etc/systemd/system/')
            os.system("sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/endlessh")

            service_config = read_file('/etc/systemd/system/endlessh.service')
            service_config = re.sub(r'^\s*#?\s*AmbientCapabilities=CAP_NET_BIND_SERVICE\s+\S+', 'AmbientCapabilities=CAP_NET_BIND_SERVICE', service_config, flags=re.MULTILINE)
            service_config = re.sub(r'^\s*#?\s*PrivateUsers=true\s+\S+', '#PrivateUsers=true', service_config, flags=re.MULTILINE)

            write_file('/etc/systemd/system/endlessh.service', service_config)

        if not os.path.exists("/etc/systemd/system/multi-user.target.wants/endlessh.service"):
            os.system('sudo systemctl --now enable endlessh')

        config_dir = '/etc/endlessh'
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)

        config_path = os.path.join(config_dir, 'config')
        if not os.path.exists(config_path):
            with open(config_path, 'w') as file:
                file.write(f'Port {tarpit_port}\n')
                file.write('LogLevel 1\n')

        if subprocess.run(['systemctl', 'is-active', '--quiet', 'endlessh']).returncode != 0:
            os.system('sudo systemctl restart endlessh')
        os.system('sudo systemctl daemon-reload')
        print(f'Endlessh setup complete. Running on port {tarpit_port}')
    else:
        print('Skipping setting up tarpit...')


def set_up_fail2ban(ask, port):
    if ask:
        allow_fail2ban = ask_permission("Do you want to set up fail2ban (brute-force protection)? (y/n) [y]: ", True)
    else:
        allow_fail2ban = True
    if not allow_fail2ban:
        print('Skipping fail2ban set up...')
        return
  
    fail2ban_installed = os.path.exists('/etc/fail2ban')

    if not fail2ban_installed:
        print("Fail2ban is not installed. Installing...")
        subprocess.run(['sudo', 'apt', 'update'])
        subprocess.run(['sudo', 'apt', 'install', 'fail2ban', '-y'])
        print("Fail2ban installed successfully.")

    fail2ban_config_path = '/etc/fail2ban/jail.conf'
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(fail2ban_config_path)

    if 'sshd' in config:
        config['sshd']['port'] = str(port)
    else:
        print("Warning: 'sshd' section not found in Fail2ban configuration.")
        return

    with open(fail2ban_config_path, 'w') as file:
        config.write(file)

    print("Restarting Fail2ban...")
    subprocess.run(['sudo', 'systemctl', 'restart', 'fail2ban'])
    print("Fail2ban restarted successfully.")


def main():
    hello_message()

    if not check_sudo():
        print('Please execute this script with sudo')
        return 1

    print('Please choose execution mode:\n')
    print('[1] SSH server autoconfig (recommended)')
    print('[2] Manual SSH server configuring')
    print('[3] Restore from backup (only after first successfull s3h run)')
    print('[4] Exit\n')
    option = int(input('Execution mode: '))
  
    if (option not in [1, 2, 3, 4]):
        print('Invalid option. Terminating...')
        return 1
  
    if option == 1:
        create_backup()
        update_port(DEFAULT_PORT)
        set_permit_root_login(ask=False)
        set_permit_password_login(ask=False)
        set_timeouts()
        set_cryptography()
        set_logging()
        set_banner(ask=False)
        set_whitelist()
        set_up_tarpit(ask=False)
        set_up_fail2ban(False, DEFAULT_PORT)
        subprocess.run(['sudo', 'systemctl', 'restart', 'ssh'])

    elif option == 2:
        create_backup()
        new_port = get_new_port()
        update_port(new_port)
        set_permit_root_login(ask=True)
        set_permit_password_login(ask=True)
        set_timeouts()
        set_cryptography()
        set_logging()
        set_banner(ask=True)
        set_whitelist()
        set_up_tarpit(ask=True)
        set_up_fail2ban(True, new_port)
        subprocess.run(['sudo', 'systemctl', 'restart', 'ssh'])

    elif option == 3:
        restore_from_backup()

    elif option == 4:
        return 0


if __name__ == "__main__":
   main()