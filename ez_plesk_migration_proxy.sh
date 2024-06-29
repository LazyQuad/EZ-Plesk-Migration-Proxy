#!/bin/bash
clear

# Set up error handling
set +e  # Don't exit on error
set +o pipefail # Don't exit if any command in a pipeline fails

# Script version
VERSION="1.2.4"

# Get the script's directory
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create necessary directories
mkdir -p "$script_dir/keys" "$script_dir/backups" "$script_dir/logs" || { echo "Failed to create required directories"; exit 1; }

# Generate unique log file name
SCRIPT_LOG="$script_dir/logs/migration_script_$(date +'%Y%m%d_%H%M%S').log"

# Initialize migration status variable
migration_status=0

# Function to log messages and echo to console
log_message() {
    local message="$1"
    echo -e "\n$(date +'%Y-%m-%d %H:%M:%S') - $message" | tee -a "$SCRIPT_LOG"
}

# Function to handle errors
handle_error() {
    log_message "Error on line $1"
    # Don't exit, just continue
}

# Set up trap for error handling
trap 'handle_error $LINENO' ERR

# Function to check if required commands are available
check_requirements() {
    local required_commands=("ssh" "scp" "dig" "tar")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_message "Error: $cmd is required but not installed on the proxy server."
            return 1
        fi
    done
    log_message "All required commands are available."
}

# Function to prompt for input with default value
prompt_input() {
    read -p "$1 [$2]: " input
    echo "${input:-$2}"
}

# Function to generate SSH key pair
generate_ssh_keys() {
    local server=$1
    local user=$2
    local key_path="$script_dir/keys/$server-$user"
    
    log_message "Generating SSH key pair for $user@$server..."
    ssh-keygen -t rsa -b 4096 -f "$key_path" -N "" || { log_message "Failed to generate SSH key pair for $user@$server"; return 1; }
}

# Function to check if SSH key is already present on the server
check_ssh_key() {
    local user=$1
    local server_ip=$2
    local port=$3
    local key_path="$script_dir/keys/$server_ip-$user"
    
    ssh-keyscan -p "$port" "$server_ip" > /dev/null 2>&1
    local exit_status=$?
    if [ $exit_status -eq 0 ]; then
        ssh -p "$port" "$user@$server_ip" "grep -q \"$(cat "$key_path.pub")\" ~/.ssh/authorized_keys"
        exit_status=$?
        if [ $exit_status -eq 0 ]; then
            log_message "SSH key is already present on $server_ip for $user"
            return 0
        fi
    fi
    return 1
}

# Function to copy public SSH key to server
copy_ssh_key() {
    local user=$1
    local server_ip=$2
    local port=$3
    local key_path="$script_dir/keys/$server_ip-$user"
    
    if ! check_ssh_key "$user" "$server_ip" "$port"; then
        log_message "Copying public SSH key to $server_ip for $user..."
        ssh-copy-id "-p $port" -i "$key_path.pub" "$user@$server_ip" || { log_message "Failed to copy SSH key to $server_ip for $user"; return 1; }
    fi
}

# Function to check if a domain exists on the target server
check_domain_exists() {
    local user=$1
    local server_ip=$2
    local domain=$3
    local port=$4
    log_message "Checking if domain $domain already exists on the target server..."
    ssh -p "$port" "$user@$server_ip" "plesk bin domain --list | grep -q $domain"
    local exit_status=$?
    if [ $exit_status -eq 0 ]; then
        log_message "Domain $domain already exists on the target server"
        return 0
    else
        return 1
    fi
}

# Function to backup domain on source server
backup_source() {
    local user=$1
    local server_ip=$2
    local domain=$3
    local port=$4
    local use_password_auth=$5
    local script_dir=$6
    
    local backup_file="/var/lib/psa/dumps/${domain}-backup.tar"
    log_message "Backing up domain $domain on the source server to $backup_file..."
    
    local backup_command="plesk bin pleskbackup --domains-name '$domain' --output-file '$backup_file'"
    local ssh_command
    
    if [ "$use_password_auth" = true ]; then
        ssh_command="ssh -p $port $user@$server_ip"
    else
        ssh_command="ssh -p $port -i '$script_dir/keys/$server_ip-$user' $user@$server_ip"
    fi
    
    local full_command="$ssh_command \"$backup_command && echo 'BACKUP_SUCCESS' || echo 'BACKUP_FAILED'\""
    
    local backup_output
    backup_output=$(eval "$full_command")
    local ssh_exit_status=$?
    
    if [[ $backup_output == *"BACKUP_SUCCESS"* ]]; then
        log_message "Backup created successfully"
        echo "SUCCESS:$backup_file"
        return 0
    else
        log_message "Failed to create backup. Error output: $backup_output"
        echo "FAILED:"
        return 1
    fi
}

# Function to restore backup on target server
restore_backup() {
    local user=$1
    local server_ip=$2
    local domain=$3
    local port=$4
    local target_backup_file=$5
    local ignore_sign=$6

    log_message "Restoring backup of domain $domain on the target server..."

    if [ "$ignore_sign" == "yes" ]; then
        ssh -p "$port" "$user@$server_ip" "plesk bin pleskrestore --restore $target_backup_file -level domains -domain-name $domain -ignore-sign" || { log_message "Failed to restore backup of domain $domain on the target server"; return 1; }
    else
        ssh -p "$port" "$user@$server_ip" "plesk bin pleskrestore --restore $target_backup_file -level domains -domain-name $domain" || { log_message "Failed to restore backup of domain $domain on the target server"; return 1; }
    fi
}

# Extract the IP address of the server using dig
extract_ip() {
    local server_input=$1
    local server_type=$2  # "source" or "target"
    
    if [[ $server_input =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$server_input"
    else
        local ip=$(dig +short "$server_input" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)
        if [[ -n $ip ]]; then
            echo "$ip:$server_input"
        else
            log_message "Failed to retrieve a valid IP address for $server_input ($server_type server). Please enter a valid IP address."
            return 1
        fi
    fi
}

# Function to check Plesk version on server
check_plesk_version() {
    local user=$1
    local server_ip=$2
    local port=$3
    log_message "Checking Plesk version on $server_ip..."
    ssh -p "$port" "$user@$server_ip" "plesk version" || { log_message "Failed to check Plesk version on $server_ip"; return 1; }
}

# Function to backup existing domain on target server
backup_existing_domain() {
    local user=$1
    local server_ip=$2
    local domain=$3
    local port=$4
    local timestamp=$(date +'%Y%m%d_%H%M%S')
    local backup_file="/var/lib/psa/dumps/${domain}-existing-backup-${timestamp}.tar"
    
    log_message "Backing up existing domain $domain on the target server..."
    ssh -p "$port" "$user@$server_ip" "plesk bin pleskbackup --domains-name $domain --output-file $backup_file" || { log_message "Failed to backup existing domain $domain on the target server"; return 1; }
}

# Function to display the authentication method menu and get user input
get_auth_method() {
    echo -e "\nAuthentication Methods:"
    echo "-----------------------"
    echo "1. Less Secure - Password-based authentication"
    echo "2. More Secure - SSH key-based authentication"
    echo 
    read -p "Enter the number corresponding to your preferred authentication method: " auth_choice
    echo

    case $auth_choice in
        1)
            log_message "You have chosen password-based authentication."
            use_password_auth=true
            ;;
        2)
            log_message "You have chosen SSH key-based authentication."
            use_password_auth=false
            ;;
        *)
            log_message "Invalid choice. Defaulting to password-based authentication."
            use_password_auth=true
            ;;
    esac
    echo
}

# Main script execution
main() {
    log_message "Starting Plesk migration script v$VERSION"

    check_requirements || { log_message "Missing required commands. Proceeding with caution."; }

    echo -e "\n-------------------------------------------------------"
    echo "Welcome to the EZ Plesk Migration Proxy Script v$VERSION"
    echo -e "-------------------------------------------------------\n"

    while true; do
        SOURCE_SERVER=$(prompt_input "Enter the source server IP or domain")
        SOURCE_SERVER_INFO=$(extract_ip "$SOURCE_SERVER" "source")
        if [ $? -eq 0 ]; then
            IFS=':' read -r SOURCE_SERVER_IP SOURCE_SERVER_DOMAIN <<< "$SOURCE_SERVER_INFO"
            break
        fi
    done

    SOURCE_PORT=$(prompt_input "Enter the SSH port for the source server" "22")
    SOURCE_USER=$(prompt_input "Enter the username for the source server" "root")

    while true; do
        TARGET_SERVER=$(prompt_input "Enter the target server IP or domain")
        TARGET_SERVER_INFO=$(extract_ip "$TARGET_SERVER" "target")
        if [ $? -eq 0 ]; then
            IFS=':' read -r TARGET_SERVER_IP TARGET_SERVER_DOMAIN <<< "$TARGET_SERVER_INFO"
            break
        fi
    done

    TARGET_PORT=$(prompt_input "Enter the SSH port for the target server" "22")
    TARGET_USER=$(prompt_input "Enter the username for the target server" "root")

    if [ -n "$SOURCE_SERVER_DOMAIN" ]; then
        log_message "Source Server: $SOURCE_SERVER_DOMAIN (IP: $SOURCE_SERVER_IP)"
    else
        log_message "Source Server IP: $SOURCE_SERVER_IP"
    fi

    if [ -n "$TARGET_SERVER_DOMAIN" ]; then
        log_message "Target Server: $TARGET_SERVER_DOMAIN (IP: $TARGET_SERVER_IP)"
    else
        log_message "Target Server IP: $TARGET_SERVER_IP"
    fi

    SOURCE_PLESK_VERSION=$(check_plesk_version "$SOURCE_USER" "$SOURCE_SERVER_IP" "$SOURCE_PORT")
    TARGET_PLESK_VERSION=$(check_plesk_version "$TARGET_USER" "$TARGET_SERVER_IP" "$TARGET_PORT")

    if [ "$SOURCE_PLESK_VERSION" != "$TARGET_PLESK_VERSION" ]; then
        log_message "Warning: Plesk versions on the source and target servers do not match."
        log_message "Source server Plesk version: $SOURCE_PLESK_VERSION"
        log_message "Target server Plesk version: $TARGET_PLESK_VERSION"
        log_message "Restoring backups across different Plesk versions may lead to compatibility issues."
        read -p "Do you want to continue with the migration using the -ignore-sign option? (yes/no) [no]: " IGNORE_SIGN
        IGNORE_SIGN=${IGNORE_SIGN:-no}
    else
        IGNORE_SIGN="no"
    fi

    clear

    get_auth_method

    if [ "$use_password_auth" = true ]; then
        if [ -n "$SOURCE_SERVER_DOMAIN" ]; then
            read -s -p "Enter the password for the source server [$SOURCE_SERVER_DOMAIN]: " SOURCE_PASSWORD
        else
            read -s -p "Enter the password for the source server [$SOURCE_SERVER_IP]: " SOURCE_PASSWORD
        fi
        echo
        if [ -n "$TARGET_SERVER_DOMAIN" ]; then
            read -s -p "Enter the password for the target server [$TARGET_SERVER_DOMAIN]: " TARGET_PASSWORD
        else
            read -s -p "Enter the password for the target server [$TARGET_SERVER_IP]: " TARGET_PASSWORD
        fi
        echo
        echo
    else
        generate_ssh_keys "$SOURCE_SERVER_IP" "$SOURCE_USER" || migration_status=1
        generate_ssh_keys "$TARGET_SERVER_IP" "$TARGET_USER" || migration_status=1
        copy_ssh_key "$SOURCE_USER" "$SOURCE_SERVER_IP" "$SOURCE_PORT" || migration_status=1
        copy_ssh_key "$TARGET_USER" "$TARGET_SERVER_IP" "$TARGET_PORT" || migration_status=1
    fi

    while true; do
        echo
        DOMAIN=$(prompt_input "Enter the domain to migrate (or press Enter to finish)")
        if [ -z "$DOMAIN" ]; then
            break
        fi
        echo

        log_message "Starting migration process for domain: $DOMAIN"
        
        MIGRATION_LOG="$script_dir/logs/migration_${DOMAIN}_$(date +'%Y%m%d_%H%M%S').log"

        if check_domain_exists "$TARGET_USER" "$TARGET_SERVER_IP" "$DOMAIN" "$TARGET_PORT"; then
            echo -e "\nDomain $DOMAIN already exists on the target server."
            BACKUP_DOMAIN=$(prompt_input "Do you want to backup the existing domain? (yes/no)" "no")
            if [ "$BACKUP_DOMAIN" == "yes" ]; then
                backup_existing_domain "$TARGET_USER" "$TARGET_SERVER_IP" "$DOMAIN" "$TARGET_PORT" || { migration_status=1; continue; }
            fi
        fi

        echo
        if [ -n "$SOURCE_SERVER_DOMAIN" ] && [ -n "$TARGET_SERVER_DOMAIN" ]; then
            read -p "Are you sure you want to proceed with the migration of domain $DOMAIN from $SOURCE_SERVER_DOMAIN ($SOURCE_SERVER_IP) to $TARGET_SERVER_DOMAIN ($TARGET_SERVER_IP)? (yes/no): " CONFIRM
        elif [ -n "$SOURCE_SERVER_DOMAIN" ]; then
            read -p "Are you sure you want to proceed with the migration of domain $DOMAIN from $SOURCE_SERVER_DOMAIN ($SOURCE_SERVER_IP) to $TARGET_SERVER_IP? (yes/no): " CONFIRM
        elif [ -n "$TARGET_SERVER_DOMAIN" ]; then
            read -p "Are you sure you want to proceed with the migration of domain $DOMAIN from $SOURCE_SERVER_IP to $TARGET_SERVER_DOMAIN ($TARGET_SERVER_IP)? (yes/no): " CONFIRM
        else
            read -p "Are you sure you want to proceed with the migration of domain $DOMAIN from $SOURCE_SERVER_IP to $TARGET_SERVER_IP? (yes/no): " CONFIRM
        fi
        echo

        if [ "$CONFIRM" != "yes" ]; then
            log_message "Migration of domain $DOMAIN aborted by the user."
            continue
        fi

        log_message "Starting backup process for domain $DOMAIN. Please wait, this may take a while..."

        BACKUP_RESULT=$(backup_source "$SOURCE_USER" "$SOURCE_SERVER_IP" "$DOMAIN" "$SOURCE_PORT" "$use_password_auth" "$script_dir")
        BACKUP_STATUS=$?

        IFS=':' read -r BACKUP_STATUS_TEXT BACKUP_FILE <<< "$BACKUP_RESULT"

        if [ "$BACKUP_STATUS_TEXT" != "SUCCESS" ]; then
            log_message "Failed to create backup for domain $DOMAIN. Skipping migration."
            migration_status=1
            continue
        fi

        log_message "Backup file path: $BACKUP_FILE"

        if [ "$use_password_auth" = true ]; then
            ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "test -f '$BACKUP_FILE'" 
            FILE_EXISTS=$?
        else
            ssh -p "$SOURCE_PORT" -i "$script_dir/keys/$SOURCE_SERVER_IP-$SOURCE_USER" "$SOURCE_USER@$SOURCE_SERVER_IP" "test -f '$BACKUP_FILE'"
            FILE_EXISTS=$?
        fi

        if [ $FILE_EXISTS -ne 0 ]; then
            log_message "Backup file not found on source server: $BACKUP_FILE"
            migration_status=1
            continue
        fi

        log_message "Backup file verified on source server: $BACKUP_FILE"

        log_message "Verifying backup integrity on source server. Please wait..."
        if [ "$use_password_auth" = true ]; then
            ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "tar -tf \"$BACKUP_FILE\"" > /dev/null 2>&1
        else
            ssh -p "$SOURCE_PORT" -i "$script_dir/keys/$SOURCE_SERVER_IP-$SOURCE_USER" "$SOURCE_USER@$SOURCE_SERVER_IP" "tar -tf \"$BACKUP_FILE\"" > /dev/null 2>&1
        fi
        
        if [ $? -ne 0 ]; then
            log_message "Backup verification failed on the source server for $BACKUP_FILE."
            read -p "Do you want to continue with the migration despite the verification failure? (yes/no): " CONTINUE_ANYWAY
            if [ "$CONTINUE_ANYWAY" != "yes" ]; then
                log_message "Skipping migration of domain $DOMAIN due to verification failure."
                migration_status=1
                continue
            else
                log_message "Continuing with migration despite verification failure."
            fi
        else
            log_message "Backup verification successful."
        fi
        log_message "Transferring backup to target server. Please wait..."

        TARGET_BACKUP_FILE="/tmp/$DOMAIN-backup.tar"
        log_message "Transferring backup of domain $DOMAIN from $BACKUP_FILE on the source server to $TARGET_BACKUP_FILE on the target server..."
        if [ "$use_password_auth" = true ]; then
            scp -P "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP:$BACKUP_FILE" "$TARGET_USER@$TARGET_SERVER_IP:$TARGET_BACKUP_FILE"
        else
            scp -P "$SOURCE_PORT" -i "$script_dir/keys/$SOURCE_SERVER_IP-$SOURCE_USER" "$SOURCE_USER@$SOURCE_SERVER_IP:$BACKUP_FILE" "$TARGET_USER@$TARGET_SERVER_IP:$TARGET_BACKUP_FILE"
        fi

        if [ $? -ne 0 ]; then
            log_message "Failed to transfer backup of domain $DOMAIN to the target server"
            migration_status=1
            continue
        fi

        log_message "Backup transfer completed successfully."

        log_message "Verifying backup integrity on target server..."
        if [ "$use_password_auth" = true ]; then
            ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "tar -tvf \"$TARGET_BACKUP_FILE\"" > /dev/null 2>&1
        else
            ssh -p "$TARGET_PORT" -i "$script_dir/keys/$TARGET_SERVER_IP-$TARGET_USER" "$TARGET_USER@$TARGET_SERVER_IP" "tar -tvf \"$TARGET_BACKUP_FILE\"" > /dev/null 2>&1
        fi
        local exit_status=$?
        if [ $exit_status -ne 0 ]; then
            log_message "Backup verification failed on the target server for $TARGET_BACKUP_FILE. Error code: $exit_status"
            log_message "Skipping migration of domain $DOMAIN."
            migration_status=1
            continue
        fi
        log_message "Backup verification on target server successful."

        restore_backup "$TARGET_USER" "$TARGET_SERVER_IP" "$DOMAIN" "$TARGET_PORT" "$TARGET_BACKUP_FILE" "$IGNORE_SIGN" || { log_message "Failed to restore backup of domain $DOMAIN on the target server"; migration_status=1; continue; }

        log_message "Migration of domain $DOMAIN completed successfully."

        echo
        read -p "Do you want to clean up the backup files for domain $DOMAIN? (yes/no) [yes]: " CLEANUP_BACKUPS
        CLEANUP_BACKUPS=${CLEANUP_BACKUPS:-yes}

        if [ "$CLEANUP_BACKUPS" == "yes" ]; then
            log_message "Cleaning up backup files for domain $DOMAIN on the source server..."
            if [ "$use_password_auth" = true ]; then
                ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "rm -f \"$BACKUP_FILE\""
            else
                ssh -p "$SOURCE_PORT" -i "$script_dir/keys/$SOURCE_SERVER_IP-$SOURCE_USER" "$SOURCE_USER@$SOURCE_SERVER_IP" "rm -f \"$BACKUP_FILE\""
            fi

            log_message "Cleaning up backup files for domain $DOMAIN on the target server..."
            if [ "$use_password_auth" = true ]; then
                ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "rm -f \"$TARGET_BACKUP_FILE\""
            else
                ssh -p "$TARGET_PORT" -i "$script_dir/keys/$TARGET_SERVER_IP-$TARGET_USER" "$TARGET_USER@$TARGET_SERVER_IP" "rm -f \"$TARGET_BACKUP_FILE\""
            fi

            log_message "Backup files for domain $DOMAIN have been cleaned up."
        else
            log_message "Backup files for domain $DOMAIN have not been cleaned up."
        fi

        echo
        log_message "Migration process for domain $DOMAIN completed."
        echo
    done

    if [ $migration_status -eq 0 ]; then
        log_message "All domain migrations completed successfully."
    else
        log_message "One or more domain migrations encountered errors. Please check the logs for more details."
    fi

    if [ "$use_password_auth" = false ]; then
        echo
        read -p "Do you want to erase the generated SSH keys? (yes/no) [yes]: " ERASE_KEYS
        ERASE_KEYS=${ERASE_KEYS:-yes}

        if [ "$ERASE_KEYS" == "yes" ]; then
            log_message "Erasing SSH key files..."
            rm -f "$script_dir/keys/$SOURCE_SERVER_IP-$SOURCE_USER" "$script_dir/keys/$SOURCE_SERVER_IP-$SOURCE_USER.pub"
            rm -f "$script_dir/keys/$TARGET_SERVER_IP-$TARGET_USER" "$script_dir/keys/$TARGET_SERVER_IP-$TARGET_USER.pub"

            log_message "SSH keys have been erased."
        else
            log_message "SSH keys have not been erased."
        fi
    fi

    log_message "Migration process completed. Check the logs for details."
}

# Run the main function
main

echo -e "\nScript execution completed. Check the log for details."