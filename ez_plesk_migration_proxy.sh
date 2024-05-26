#!/bin/bash
clear

# Function to prompt for input with default value
prompt_input() {
  read -p "$1 [$2]: " input
  echo "${input:-$2}"
}

# Log function to log messages using logger and echo
log_message() {
  local message="$1"
  logger -t "plesk-migrate" "$message"
  echo "$message"
}

# Function to generate SSH key pair
generate_ssh_keys() {
  log_message "Generating SSH key pair..."
  ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" || { log_message "Failed to generate SSH key pair"; exit 1; }
}

# Function to copy public SSH key to server
copy_ssh_key() {
  local user=$1
  local server_ip=$2
  local port=$3
  log_message "Copying public SSH key to $server_ip..."
  ssh-copy-id "-p $port" $user@$server_ip || { log_message "Failed to copy SSH key to $server_ip"; exit 1; }
}

# Function to check if a domain exists on the target server
check_domain_exists() {
  local user=$1
  local server_ip=$2
  local domain=$3
  local port=$4
  log_message "Checking if domain $domain already exists on the target server..."
  ssh "-p $port" $user@$server_ip "plesk bin domain --list | grep -q $domain"
  if [ $? -eq 0 ]; then
    log_message "Domain $domain already exists on the target server"
    return 0
  else
    return 1
  fi
}

# Function to backup domain on target server
backup_existing_domain() {
  local user=$1
  local server_ip=$2
  local domain=$3
  local port=$4
  log_message "Backing up existing domain $domain on the target server..."
  ssh "-p $port" $user@$server_ip "plesk bin pleskbackup --domains-name $domain --output-file /var/lib/psa/dumps/$domain-backup-$(date +%Y%m%d%H%M%S).tar" || { log_message "Failed to backup domain $domain on the target server"; exit 1; }
}

# Function to restore backup on target server
restore_backup() {
  local user=$1
  local server_ip=$2
  local domain=$3
  local port=$4
  log_message "Restoring backup of domain $domain on the target server..."
  ssh "-p $port" $user@$server_ip "plesk bin pleskrestore --restore /tmp/$domain-backup.tar -level domains -domain $domain" || { log_message "Failed to restore backup of domain $domain on the target server"; exit 1; }
}

# Function to update DNS entries on target server
update_dns() {
  local user=$1
  local server_ip=$2
  local domain=$3
  local port=$4
  log_message "Updating DNS entries for domain $domain on the target server..."
  ssh "-p $port" $user@$server_ip "plesk bin dns --update $domain -a $server_ip" || { log_message "Failed to update DNS entries for domain $domain on the target server"; exit 1; }
}

# Check if arguments are provided
if [ $# -eq 8 ]; then
  SOURCE_SERVER=$1
  SOURCE_PORT=$2
  SOURCE_USER=$3
  TARGET_SERVER=$4
  TARGET_PORT=$5
  TARGET_USER=$6
  DOMAIN=$7
  UPDATE_DNS=$8
else
  # Prompt user for necessary information
  echo "Welcome to the EZ Plesk Migration Proxy Script"
  echo "--------------------------------------------"

  SOURCE_SERVER=$(prompt_input "Enter the source server IP")
  SOURCE_PORT=$(prompt_input "Enter the SSH port for the source server" "22")
  SOURCE_USER=$(prompt_input "Enter the username for the source server" "root")
  TARGET_SERVER=$(prompt_input "Enter the target server IP")
  TARGET_PORT=$(prompt_input "Enter the SSH port for the target server" "22")
  TARGET_USER=$(prompt_input "Enter the username for the target server" "root")
  DOMAIN=$(prompt_input "Enter the domain to migrate")
  UPDATE_DNS=$(prompt_input "Do you want to update DNS with the new server IP? (yes/no)" "yes")
fi

# Generate SSH key pair
generate_ssh_keys || { log_message "Failed to generate SSH key pair"; exit 1; }

# Copy public SSH key to source server
copy_ssh_key $SOURCE_USER $SOURCE_SERVER $SOURCE_PORT

# Copy public SSH key to target server
copy_ssh_key $TARGET_USER $TARGET_SERVER $TARGET_PORT

# Check if domain exists on target server
if check_domain_exists $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT; then
  echo "Domain $DOMAIN already exists on the target server."
  BACKUP_DOMAIN=$(prompt_input "Do you want to backup the existing domain? (yes/no)" "no")
  if [ "$BACKUP_DOMAIN" == "yes" ]; then
    backup_existing_domain $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT
  fi
fi

# Confirmation prompt before proceeding
read -p "Are you sure you want to proceed with the migration of domain $DOMAIN? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  log_message "Migration aborted by the user."
  exit 0
fi

# Backup domain on source server
log_message "Backing up domain $DOMAIN on the source server..."
ssh "-p $SOURCE_PORT" $SOURCE_USER@$SOURCE_SERVER "plesk bin pleskbackup --domains-name $DOMAIN --output-file /var/lib/psa/dumps/$DOMAIN-backup.tar" || { log_message "Failed to backup domain $DOMAIN on the source server"; exit 1; }

# Verify backup integrity on source server
ssh "-p $SOURCE_PORT" $SOURCE_USER@$SOURCE_SERVER "tar -tvf /var/lib/psa/dumps/$DOMAIN-backup.tar" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  log_message "Backup verification failed on the source server. Aborting migration."
  exit 1
fi

# Transfer backup from source server to target server
log_message "Transferring backup of domain $DOMAIN from source server to target server..."
scp "-P $SOURCE_PORT" $SOURCE_USER@$SOURCE_SERVER:/var/lib/psa/dumps/$DOMAIN-backup.tar /tmp/ || { log_message "Failed to transfer backup of domain $DOMAIN from source server to target server"; exit 1; }

# Verify backup integrity on target server
ssh "-p $TARGET_PORT" $TARGET_USER@$TARGET_SERVER "tar -tvf /tmp/$DOMAIN-backup.tar" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  log_message "Backup verification failed on the target server. Aborting migration."
  exit 1
fi

# Restore backup on target server
restore_backup $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT

# Modify DNS entries on target server if needed
if [ "$UPDATE_DNS" == "yes" ]; then
  update_dns $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT
fi

log_message "Migration of domain $DOMAIN completed successfully."
exit 0