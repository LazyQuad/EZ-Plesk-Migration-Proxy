#!/bin/bash

VERSION="1.3.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/migration_$(date +'%Y%m%d_%H%M%S').log"

log_message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

prompt_input() {
    read -p "$1 [$2]: " input
    echo "${input:-$2}"
}

check_ssh_connection() {
    local user_host=$1
    local port=$2
    ssh -q -o BatchMode=yes -o ConnectTimeout=5 -p "$port" "$user_host" "echo 2>&1" >/dev/null
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

main() {
    log_message "Starting Plesk migration script v$VERSION"

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
    if ! check_ssh_connection "$SOURCE_USER@$SOURCE_SERVER_IP" "$SOURCE_PORT"; then
        log_message "Cannot connect to source server. Please check your credentials and try again."
        return 1
    fi

    if ! check_ssh_connection "$TARGET_USER@$TARGET_SERVER_IP" "$TARGET_PORT"; then
        log_message "Cannot connect to target server. Please check your credentials and try again."
        return 1
    fi

    # Main migration loop
    while true; do
        DOMAIN=$(prompt_input "Enter the domain to migrate (or press Enter to finish)" "")
        [ -z "$DOMAIN" ] && break

        log_message "Starting migration for domain: $DOMAIN"

        # Check if domain exists on source
        if ! ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "plesk bin domain --info $DOMAIN" &>/dev/null; then
            log_message "Domain $DOMAIN does not exist on source server. Skipping."
            continue
        fi

        # Check if domain exists on target
        if ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "plesk bin domain --info $DOMAIN" &>/dev/null; then
            log_message "Domain $DOMAIN already exists on target server. Skipping."
            continue
        fi

        # Backup domain on source server
        BACKUP_FILE="/tmp/${DOMAIN}_backup.tar"
        log_message "Backing up domain $DOMAIN on source server..."
        if ! ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "plesk bin pleskbackup --domains-name $DOMAIN --output-file $BACKUP_FILE"; then
            log_message "Failed to create backup for domain $DOMAIN. Skipping."
            continue
        fi

        # Transfer backup to target server
        log_message "Transferring backup to target server..."
        if ! scp -P "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP:$BACKUP_FILE" "$TARGET_USER@$TARGET_SERVER_IP:$BACKUP_FILE"; then
            log_message "Failed to transfer backup for domain $DOMAIN. Skipping."
            continue
        fi

        # Restore backup on target server
        log_message "Restoring backup on target server..."
        if ! ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "plesk bin pleskrestore --restore $BACKUP_FILE -level domains -domain-name $DOMAIN"; then
            log_message "Failed to restore backup for domain $DOMAIN on target server."
        else
            log_message "Successfully migrated domain $DOMAIN"
        fi

        # Clean up
        ssh -p "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER_IP" "rm -f $BACKUP_FILE"
        ssh -p "$TARGET_PORT" "$TARGET_USER@$TARGET_SERVER_IP" "rm -f $BACKUP_FILE"
    done

    log_message "Migration process completed. Check the log for details."
    return 0
}

main