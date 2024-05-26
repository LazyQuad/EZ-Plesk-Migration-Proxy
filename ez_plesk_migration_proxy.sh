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

# Function to log current working directory
log_directory() {
  local message="$1"
  local directory=$(pwd)
  log_message "$message: $directory"
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
  
  ssh-keyscan -p $port $server_ip > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    ssh -p $port $user@$server_ip "grep -q \"$(cat "$key_path.pub")\" ~/.ssh/authorized_keys"
    if [ $? -eq 0 ]; then
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
  
  if ! check_ssh_key $user $server_ip $port; then
    log_message "Copying public SSH key to $server_ip for $user..."
    ssh-copy-id "-p $port" -i "$key_path.pub" $user@$server_ip || { log_message "Failed to copy SSH key to $server_ip for $user"; return 1; }
  fi
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
  ssh "-p $port" $user@$server_ip "plesk bin pleskbackup --domains-name $domain --output-file /var/lib/psa/dumps/$domain-backup-$(date +%Y%m%d%H%M%S).tar" || { log_message "Failed to backup domain $domain on the target server"; return 1; }
}

# Function to restore backup on target server
restore_backup() {
  local user=$1
  local server_ip=$2
  local domain=$3
  local port=$4
  log_message "Restoring backup of domain $domain on the target server..."
  ssh "-p $port" $user@$server_ip "plesk bin pleskrestore --restore /tmp/$domain-backup.tar -level domains -domain-name $domain" || { log_message "Failed to restore backup of domain $domain on the target server"; return 1; }
}

# Function to update DNS entries on target server
update_dns() {
  local user=$1
  local server_ip=$2
  local domain=$3
  local port=$4
  log_message "Updating DNS entries for domain $domain on the target server..."
  ssh "-p $port" $user@$server_ip "plesk bin dns --add $domain -a $server_ip" || { log_message "Failed to update DNS entries for domain $domain on the target server"; return 1; }
}

# Function to display the authentication method menu and get user input
get_auth_method() {
  echo "Authentication Methods:"
  echo "1. Password-based authentication"
  echo "2. SSH key-based authentication"
  read -p "Enter the number corresponding to your preferred authentication method: " auth_choice

  case $auth_choice in
    1)
      echo "You have chosen password-based authentication."
      echo "Please note that password-based authentication is less secure compared to SSH key-based authentication."
      echo "Risks:"
      echo "- Passwords can be intercepted if transmitted over an unencrypted or improperly secured connection."
      echo "- Passwords are susceptible to brute-force and dictionary attacks."
      echo "- Passwords can be accidentally disclosed or shared, leading to unauthorized access."
      use_password_auth=true
      ;;
    2)
      echo "You have chosen SSH key-based authentication."
      echo "SSH key-based authentication provides a more secure method of authentication."
      echo "Risks:"
      echo "- Private keys must be kept secure and protected from unauthorized access."
      echo "- If a private key is compromised, it can be used for unauthorized access to the corresponding servers."
      use_password_auth=false
      ;;
    *)
      echo "Invalid choice. Defaulting to password-based authentication."
      use_password_auth=true
      ;;
  esac
}

# Get the script's directory
script_dir="$(dirname "$(readlink -f "$0")")"

# Create the keys directory if it doesn't exist
mkdir -p "$script_dir/keys"

# Initialize migration status variable
migration_status=0

# Prompt user for source and target server details
echo "Welcome to the EZ Plesk Migration Proxy Script"
echo "--------------------------------------------"

SOURCE_SERVER=$(prompt_input "Enter the source server IP")
SOURCE_PORT=$(prompt_input "Enter the SSH port for the source server" "22")
SOURCE_USER=$(prompt_input "Enter the username for the source server" "root")

TARGET_SERVER=$(prompt_input "Enter the target server IP")
TARGET_PORT=$(prompt_input "Enter the SSH port for the target server" "22")
TARGET_USER=$(prompt_input "Enter the username for the target server" "root")

UPDATE_DNS=$(prompt_input "Do you want to update DNS with the new server IP? (yes/no)" "yes")

# Prompt user to choose the authentication method
get_auth_method

if [ "$use_password_auth" = true ]; then
  # Prompt for passwords
  read -s -p "Enter the password for the source server: " SOURCE_PASSWORD
  echo
  read -s -p "Enter the password for the target server: " TARGET_PASSWORD
  echo
else
  # Generate SSH key pair for source server
  generate_ssh_keys $SOURCE_SERVER $SOURCE_USER || migration_status=1

  # Generate SSH key pair for target server
  generate_ssh_keys $TARGET_SERVER $TARGET_USER || migration_status=1

  # Copy public SSH key to source server
  copy_ssh_key $SOURCE_USER $SOURCE_SERVER $SOURCE_PORT || migration_status=1

  # Copy public SSH key to target server
  copy_ssh_key $TARGET_USER $TARGET_SERVER $TARGET_PORT || migration_status=1
fi

# Loop to transfer multiple domains
while true; do
  # Prompt user for domain to migrate
  DOMAIN=$(prompt_input "Enter the domain to migrate (or press Enter to finish)")
  if [ -z "$DOMAIN" ]; then
    break
  fi

  # Check if domain exists on target server
  if check_domain_exists $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT; then
    echo "Domain $DOMAIN already exists on the target server."
    BACKUP_DOMAIN=$(prompt_input "Do you want to backup the existing domain? (yes/no)" "no")
    if [ "$BACKUP_DOMAIN" == "yes" ]; then
      backup_existing_domain $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT || migration_status=1
    fi
  fi

  # Confirmation prompt before proceeding
  read -p "Are you sure you want to proceed with the migration of domain $DOMAIN? (yes/no): " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    log_message "Migration of domain $DOMAIN aborted by the user."
    continue
  fi

  # Backup domain on source server
  BACKUP_FILE="/var/lib/psa/dumps/$DOMAIN-backup.tar"
  log_message "Backing up domain $DOMAIN on the source server to $BACKUP_FILE..."
  if [ "$use_password_auth" = true ]; then
    ssh "-p $SOURCE_PORT" $SOURCE_USER@$SOURCE_SERVER "plesk bin pleskbackup --domains-name $DOMAIN --output-file $BACKUP_FILE" || migration_status=1
  else
    ssh "-p $SOURCE_PORT" -i "$script_dir/keys/$SOURCE_SERVER-$SOURCE_USER" $SOURCE_USER@$SOURCE_SERVER "plesk bin pleskbackup --domains-name $DOMAIN --output-file $BACKUP_FILE" || migration_status=1
  fi

  # Verify backup integrity on source server
  if [ "$use_password_auth" = true ]; then
    ssh "-p $SOURCE_PORT" $SOURCE_USER@$SOURCE_SERVER "tar -tvf $BACKUP_FILE" > /dev/null 2>&1
  else
    ssh "-p $SOURCE_PORT" -i "$script_dir/keys/$SOURCE_SERVER-$SOURCE_USER" $SOURCE_USER@$SOURCE_SERVER "tar -tvf $BACKUP_FILE" > /dev/null 2>&1
  fi
  if [ $? -ne 0 ]; then
    log_message "Backup verification failed on the source server for $BACKUP_FILE. Skipping migration of domain $DOMAIN."
    migration_status=1
    continue
  fi

  # Transfer backup from source server to target server
  TARGET_BACKUP_FILE="/tmp/$DOMAIN-backup.tar"
  log_message "Transferring backup of domain $DOMAIN from $BACKUP_FILE on the source server to $TARGET_BACKUP_FILE on the target server..."
  if [ "$use_password_auth" = true ]; then
    scp "-P $SOURCE_PORT" $SOURCE_USER@$SOURCE_SERVER:$BACKUP_FILE $TARGET_USER@$TARGET_SERVER:$TARGET_BACKUP_FILE || migration_status=1
  else
    scp "-P $SOURCE_PORT" -i "$script_dir/keys/$SOURCE_SERVER-$SOURCE_USER" $SOURCE_USER@$SOURCE_SERVER:$BACKUP_FILE $TARGET_USER@$TARGET_SERVER:$TARGET_BACKUP_FILE || migration_status=1
  fi

  # Verify backup integrity on target server
  if [ "$use_password_auth" = true ]; then
    ssh "-p $TARGET_PORT" $TARGET_USER@$TARGET_SERVER "tar -tvf $TARGET_BACKUP_FILE" > /dev/null 2>&1
  else
    ssh "-p $TARGET_PORT" -i "$script_dir/keys/$TARGET_SERVER-$TARGET_USER" $TARGET_USER@$TARGET_SERVER "tar -tvf $TARGET_BACKUP_FILE" > /dev/null 2>&1
  fi
  if [ $? -ne 0 ]; then
    log_message "Backup verification failed on the target server for $TARGET_BACKUP_FILE. Skipping migration of domain $DOMAIN."
    migration_status=1
    continue
  fi

  # Restore backup on target server
  restore_backup $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT || migration_status=1

  # Modify DNS entries on target server if needed
  if [ "$UPDATE_DNS" == "yes" ]; then
    update_dns $TARGET_USER $TARGET_SERVER $DOMAIN $TARGET_PORT || migration_status=1
  fi

  log_message "Migration of domain $DOMAIN completed."
done

# Display overall migration status
if [ $migration_status -eq 0 ]; then
  log_message "All domain migrations completed successfully."
else
  log_message "One or more domain migrations encountered errors. Please check the logs for more details."
fi

# Prompt user to erase SSH keys
if [ "$use_password_auth" = false ]; then
  read -p "Do you want to erase the generated SSH keys? (yes/no) [yes]: " ERASE_KEYS
  ERASE_KEYS=${ERASE_KEYS:-yes}

  if [ "$ERASE_KEYS" == "yes" ]; then
    # Erase SSH key files
    log_message "Erasing SSH key files..."
    rm -f "$script_dir/keys/$SOURCE_SERVER-$SOURCE_USER" "$script_dir/keys/$SOURCE_SERVER-$SOURCE_USER.pub"
    rm -f "$script_dir/keys/$TARGET_SERVER-$TARGET_USER" "$script_dir/keys/$TARGET_SERVER-$TARGET_USER.pub"

    log_message "SSH keys have been erased."
  else
    log_message "SSH keys have not been erased."
  fi
fi