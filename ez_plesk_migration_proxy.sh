#!/bin/bash

VERSION="1.3.0"
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
    ssh -q -o BatchMode=yes -o ConnectTimeout=5 "$1" exit
    return $?
}

main() {
    log_message "Starting Plesk migration script v$VERSION"

    # Gather server information
    SOURCE_SERVER=$(prompt_input "Enter the source server IP or domain" "")
    SOURCE_PORT=$(prompt_input "Enter the SSH port for the source server" "22")
    SOURCE_USER=$(prompt_input "Enter the username for the source server" "root")

    TARGET_SERVER=$(prompt_input "Enter the target server IP or domain" "")
    TARGET_PORT=$(prompt_input "Enter the SSH port for the target server" "22")
    TARGET_USER=$(prompt_input "Enter the username for the target server" "root")

    # Test SSH connections
    if ! check_ssh_connection "$SOURCE_USER@$SOURCE_SERVER -p $SOURCE_PORT"; then
        log_message "Cannot connect to source server. Please check your credentials and try again."
        exit 1
    fi

    if ! check_ssh_connection "$TARGET_USER@$TARGET_SERVER -p $TARGET_PORT"; then
        log_message "Cannot connect to target server. Please check your credentials and try again."
        exit 1
    }

    # Main migration loop
    while true; do
        DOMAIN=$(prompt_input "Enter the domain to migrate (or press Enter to finish)" "")
        [ -z "$DOMAIN" ] && break

        log_message "Starting migration for domain: $DOMAIN"

        # Check if domain exists on source
        if ! ssh "$SOURCE_USER@$SOURCE_SERVER" -p "$SOURCE_PORT" "plesk bin domain --info $DOMAIN" &>/dev/null; then
            log_message "Domain $DOMAIN does not exist on source server. Skipping."
            continue
        }

        # Check if domain exists on target
        if ssh "$TARGET_USER@$TARGET_SERVER" -p "$TARGET_PORT" "plesk bin domain --info $DOMAIN" &>/dev/null; then
            log_message "Domain $DOMAIN already exists on target server. Skipping."
            continue
        }

        # Backup domain on source server
        BACKUP_FILE="/tmp/${DOMAIN}_backup.tar"
        log_message "Backing up domain $DOMAIN on source server..."
        if ! ssh "$SOURCE_USER@$SOURCE_SERVER" -p "$SOURCE_PORT" "plesk bin pleskbackup --domains-name $DOMAIN --output-file $BACKUP_FILE"; then
            log_message "Failed to create backup for domain $DOMAIN. Skipping."
            continue
        fi

        # Transfer backup to target server
        log_message "Transferring backup to target server..."
        if ! scp -P "$SOURCE_PORT" "$SOURCE_USER@$SOURCE_SERVER:$BACKUP_FILE" "$TARGET_USER@$TARGET_SERVER:$BACKUP_FILE"; then
            log_message "Failed to transfer backup for domain $DOMAIN. Skipping."
            continue
        fi

        # Restore backup on target server
        log_message "Restoring backup on target server..."
        if ! ssh "$TARGET_USER@$TARGET_SERVER" -p "$TARGET_PORT" "plesk bin pleskrestore --restore $BACKUP_FILE -level domains -domain-name $DOMAIN"; then
            log_message "Failed to restore backup for domain $DOMAIN on target server."
        else
            log_message "Successfully migrated domain $DOMAIN"
        fi

        # Clean up
        ssh "$SOURCE_USER@$SOURCE_SERVER" -p "$SOURCE_PORT" "rm -f $BACKUP_FILE"
        ssh "$TARGET_USER@$TARGET_SERVER" -p "$TARGET_PORT" "rm -f $BACKUP_FILE"
    done

    log_message "Migration process completed. Check the log for details."
}

main