#!/bin/bash

VERSION="1.4.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/migration_$(date +'%Y%m%d_%H%M%S').log"

log_message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

prompt_input() {
    read -p "$1 [$2]: " input
    echo "${input:-$2}"
}

prompt_password() {
    read -s -p "$1: " password
    echo "$password"
}

check_sshpass() {
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass is not installed. It's required for this script to function."
        echo "On Ubuntu/Debian, you can install it with: sudo apt install sshpass"
        echo "On CentOS/RHEL, you can install it with: sudo yum install sshpass"
        return 1
    fi
    return 0
}

check_ssh_connection() {
    local user_host=$1
    local port=$2
    local password=$3
    sshpass -p "$password" ssh -q -o BatchMode=yes -o ConnectTimeout=5 -p "$port" "$user_host" "echo 2>&1" >/dev/null
    return $?
}

extract_ip() {
    local server_input=$1
    local server_type=$2

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

check_plesk_version() {
    local user=$1
    local server_ip=$2
    local port=$3
    local password=$4
    log_message "Checking Plesk version on $server_ip..."
    sshpass -p "$password" ssh -p "$port" "$user@$server_ip" "plesk version" 2>/dev/null || echo "Plesk not found"
}

main() {
    log_message "Starting Plesk migration script v$VERSION"

    if ! check_sshpass; then
        log_message "sshpass is required but not installed. Please install it and try again."
        return 1
    fi

    # Gather server information
    while true; do
        SOURCE_SERVER=$(prompt_input "Enter the source server IP or domain" "")
        SOURCE_SERVER_INFO=$(extract_ip "$SOURCE_SERVER" "source")
        if [ $? -eq 0 ]; then
            IFS=':' read -r SOURCE_SERVER_IP SOURCE_SERVER_DOMAIN <<< "$SOURCE_SERVER_INFO"
            break
        fi
    done

    SOURCE_PORT=$(prompt_input "Enter the SSH port for the source server" "22")
    SOURCE_USER=$(prompt_input "Enter the username for the source server" "root")
    SOURCE_PASSWORD=$(prompt_password "Enter the password for the source server")
    echo  # Add a newline after password input

    while true; do
        TARGET_SERVER=$(prompt_input "Enter the target server IP or domain" "")
        TARGET_SERVER_INFO=$(extract_ip "$TARGET_SERVER" "target")
        if [ $? -eq 0 ]; then
            IFS=':' read -r TARGET_SERVER_IP TARGET_SERVER_DOMAIN <<< "$TARGET_SERVER_INFO"
            break
        fi
    done

    TARGET_PORT=$(prompt_input "Enter the SSH port for the target server" "22")
    TARGET_USER=$(prompt_input "Enter the username for the target server" "root")
    TARGET_PASSWORD=$(prompt_password "Enter the password for the target server")
    echo  # Add a newline after password input

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

    # Test SSH connections
    if ! check_ssh_connection "$SOURCE_USER@$SOURCE_SERVER_IP" "$SOURCE_PORT" "$SOURCE_PASSWORD"; then
        log_message "Cannot connect to source server. Please check your credentials and try again."
        return 1
    fi

    if ! check_ssh_connection "$TARGET_USER@$TARGET_SERVER_IP" "$TARGET_PORT" "$TARGET_PASSWORD"; then
        log_message "Cannot connect to target server. Please check your credentials and try again."
        return 1
    fi

    # Check Plesk versions
    SOURCE_PLESK_VERSION=$(check_plesk_version "$SOURCE_USER" "$SOURCE_SERVER_IP" "$SOURCE_PORT" "$SOURCE_PASSWORD")
    TARGET_PLESK_VERSION=$(check_plesk_version "$TARGET_USER" "$TARGET_SERVER_IP" "$TARGET_PORT" "$TARGET_PASSWORD")

    log_message "Source Plesk version: $SOURCE_PLESK_VERSION"
    log_message "Target Plesk version: $TARGET_PLESK_VERSION"

    if [ "$SOURCE_PLESK_VERSION" != "$TARGET_PLESK_VERSION" ] || [ "$SOURCE_PLESK_VERSION" = "Plesk not found" ] || [ "$TARGET_PLESK_VERSION" = "Plesk not found" ]; then
        log_message "Warning: Plesk versions on the source and target servers do not match or Plesk is not installed on one of the servers."
        read -p "Do you want to use the -ignore-sign option for restoring backups? (yes/no) [yes]: " IGNORE_SIGN
        IGNORE_SIGN=${IGNORE_SIGN:-yes}
    else
        IGNORE_SIGN="no"
    fi

    # Main migration loop
    while true; do
        DOMAIN=$(prompt_input "Enter the domain to migrate (or press Enter to finish)" "")
        [ -z "$DOMAIN" ] && break

        log_message "Starting migration for domain: $DOMAIN"

        # Check if domain exists on source
        if ! sshpass -p "$SOURCE_PASSWORD" ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "plesk bin domain --info $DOMAIN" &>/dev/null; then
            log_message "Domain $DOMAIN does not exist on source server. Skipping."
            continue
        fi

        # Check if domain exists on target
        if sshpass -p "$TARGET_PASSWORD" ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "plesk bin domain --info $DOMAIN" &>/dev/null; then
            log_message "Domain $DOMAIN already exists on target server. Skipping."
            continue
        fi

        # Backup domain on source server
        BACKUP_FILE="/tmp/${DOMAIN}_backup.tar"
        log_message "Backing up domain $DOMAIN on source server..."
        if ! sshpass -p "$SOURCE_PASSWORD" ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "plesk bin pleskbackup --domains-name $DOMAIN --output-file $BACKUP_FILE"; then
            log_message "Failed to create backup for domain $DOMAIN. Skipping."
            continue
        fi

        # Transfer backup to target server
        log_message "Transferring backup to target server..."
        if ! sshpass -p "$SOURCE_PASSWORD" scp -P "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP:$BACKUP_FILE" "$TARGET_USER@$TARGET_SERVER_IP:$BACKUP_FILE"; then
            log_message "Failed to transfer backup for domain $DOMAIN. Skipping."
            continue
        fi

        # Restore backup on target server
        log_message "Restoring backup on target server..."
        RESTORE_CMD="plesk bin pleskrestore --restore $BACKUP_FILE -level domains -domain-name $DOMAIN"
        if [ "$IGNORE_SIGN" = "yes" ]; then
            RESTORE_CMD="$RESTORE_CMD -ignore-sign"
        fi
        if ! sshpass -p "$TARGET_PASSWORD" ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "$RESTORE_CMD"; then
            log_message "Failed to restore backup for domain $DOMAIN on target server."
        else
            log_message "Successfully migrated domain $DOMAIN"
        fi

        # Clean up
        sshpass -p "$SOURCE_PASSWORD" ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "rm -f $BACKUP_FILE"
        sshpass -p "$TARGET_PASSWORD" ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "rm -f $BACKUP_FILE"
    done

    log_message "Migration process completed. Check the log for details."
    return 0
}

main