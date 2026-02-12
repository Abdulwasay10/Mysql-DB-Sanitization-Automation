#!/bin/bash

set -euo pipefail

# Database credentials (will be fetched from AWS Secrets Manager)
DB_SECRET_NAME="your_sql_creds"  # Name of the secret in AWS Secrets Manager
AWS_PROFILE="your_aws_profile"

# Fetch the credentials from AWS Secrets Manager
DB_CREDENTIALS_JSON=$(aws secretsmanager get-secret-value --secret-id "$DB_SECRET_NAME" --query 'SecretString' --output text --profile "$AWS_PROFILE")

# Extract credentials using jq
DB_USER=$(echo "$DB_CREDENTIALS_JSON" | jq -r '.username')  # Extract MySQL username
DB_PASSWORD=$(echo "$DB_CREDENTIALS_JSON" | jq -r '.password')  # Extract MySQL password
DB_HOST=$(echo "$DB_CREDENTIALS_JSON" | jq -r '.host')

# Path for the temporary .my.cnf file
MY_CNF_FILE="/tmp/.my.cnf"

# Create the .my.cnf file with the credentials
echo "[client]" > "$MY_CNF_FILE"
echo "user=$DB_USER" >> "$MY_CNF_FILE"
echo "password=$DB_PASSWORD" >> "$MY_CNF_FILE"
echo "host=$DB_HOST" >> "$MY_CNF_FILE"

# Make the .my.cnf file readable only by the current user
chmod 600 "$MY_CNF_FILE"

# Database names
DB_NAME_PROD="db_prod"               # The original database (prod)
DB_NAME_PRODCLONE="db_prod_clone"    # The new cloned database

# Dump data from the original prod database and restore to prodclone
echo "Dumping data from $DB_NAME_PROD and restoring to $DB_NAME_PRODCLONE..."

# Dump the original prod database to a temporary file
mysqldump --defaults-file="$MY_CNF_FILE" "$DB_NAME_PROD" > prod_dump.sql

# Drop the database if it exists
echo "Dropping database $DB_NAME_PRODCLONE if it exists..."
mysql --defaults-file="$MY_CNF_FILE" -e "DROP DATABASE IF EXISTS $DB_NAME_PRODCLONE;"

# Create the new database
echo "Creating database $DB_NAME_PRODCLONE..."
mysql --defaults-file="$MY_CNF_FILE" -e "CREATE DATABASE $DB_NAME_PRODCLONE;"

# Restore the dump into the new prodclone database
mysql --defaults-file="$MY_CNF_FILE" "$DB_NAME_PRODCLONE" < prod_dump.sql

# Clean up the temporary dump file
rm -f prod_dump.sql

echo "Database $DB_NAME_PRODCLONE has been dropped, recreated, and populated with data from $DB_NAME_PROD."

# List of specific columns to sanitize (Table Name => Columns)
declare -A columns_to_sanitize
columns_to_sanitize=(
)

# List of tables to sanitize entirely
tables_to_sanitize_whole=(
  "users"
  "projects"
  "projects_users"
  "team"
    # Whole table to be sanitized
)

# Function to sanitize text columns in a table
sanitize_text_columns() {
  local table=$1
  local column=$2
  echo "Sanitizing text data in column: $column of table: $table"

  # Update the column with sanitized data
  mysql --defaults-file="$MY_CNF_FILE" -e "
    UPDATE $DB_NAME_PRODCLONE.$table
    SET $column = CASE
      WHEN $column LIKE '%@%' THEN 'sanitize@sanitize.com'
      WHEN $column REGEXP '^([0-9]{5})[-]?([0-9]{7})[-]?([0-9]{1})([0-9]+)?$' THEN '00000-0000000-0'
      WHEN $column LIKE 'http%' THEN 'https://sanitized.com/cnic_sanitized/sanitized.jpg'
      ELSE 'sanitize'
    END;
  "
}

# Function to sanitize numeric columns in a table
sanitize_numeric_columns() {
  local table=$1
  local column=$2
  echo "Sanitizing numeric data in column: $column of table: $table"

  # Update the column with sanitized numeric data (0)
  mysql --defaults-file="$MY_CNF_FILE" -e "
    UPDATE $DB_NAME_PRODCLONE.$table
    SET $column = 0;
  "
}

# Function to sanitize date-related columns in a table
sanitize_date_columns() {
  local table=$1
  local column=$2
  echo "Sanitizing date data in column: $column of table: $table"

  # Update the column with sanitized date (1970-01-01)
  mysql --defaults-file="$MY_CNF_FILE" -e "
    UPDATE $DB_NAME_PRODCLONE.$table
    SET $column = '1970-01-01';
  "
}

# Function to sanitize timestamp columns in a table
sanitize_null() {
  local table=$1
  local column=$2
  echo "Sanitizing timestamp data in column: $column of table: $table"

  # Use NULL if the timestamp column doesn't allow '1970-01-01 00:00:00'
  mysql --defaults-file="$MY_CNF_FILE" -e "
    UPDATE $DB_NAME_PRODCLONE.$table
    SET $column = NULL;
  "
}

# Function to sanitize ENUM columns in a table
sanitize_enum_columns() {
  local table=$1
  local column=$2
  echo "Sanitizing ENUM data in column: $column of table: $table"

  # Query for the valid ENUM values for the column
  valid_enum_values=$(mysql --defaults-file="$MY_CNF_FILE" -e "
    SELECT COLUMN_TYPE 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = '$table' AND COLUMN_NAME = '$column' AND TABLE_SCHEMA = '$DB_NAME_PRODCLONE';
  " | tail -n +2 | sed -e 's/.*enum(\(.*\))/\1/' -e 's/,/\n/g' | tr -d "'" | head -n 1)

  # If valid ENUM values are found, use the first one for sanitization
  if [[ -n "$valid_enum_values" ]]; then
    first_enum_value=$(echo "$valid_enum_values" | awk -F',' '{print $1}' | xargs)  # Take the first value from the list
    echo "Using '$first_enum_value' as sanitized value for ENUM column $column in table $table"
    mysql --defaults-file="$MY_CNF_FILE" -e "
      UPDATE $DB_NAME_PRODCLONE.$table
      SET $column = '$first_enum_value';
    "
  else
    echo "No valid ENUM values found for $column in $table. Skipping sanitization."
  fi
}

# Function to sanitize binary columns (BIT or TINYINT(1)) in a table
sanitize_binary_columns() {
  local table=$1
  local column=$2
  echo "Sanitizing binary data in column: $column of table: $table"

  # Update the column with sanitized binary data (0)
  mysql --defaults-file="$MY_CNF_FILE" -e "
    UPDATE $DB_NAME_PRODCLONE.$table
    SET $column = 0;
  "
}

# Function to sanitize all columns of a table
sanitize_all_columns() {
  local table=$1
  echo "Sanitizing all columns in table: $table"

  # Get the column names for the table
  columns=$(mysql --defaults-file="$MY_CNF_FILE" -e "
    SELECT COLUMN_NAME
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_NAME = '$table' AND TABLE_SCHEMA = '$DB_NAME_PRODCLONE';
  " | tail -n +2)  # Skipping header row

  # Loop through each column and sanitize it
  for column in $columns; do
    # Check column type to decide which sanitization function to call
    column_type=$(mysql --defaults-file="$MY_CNF_FILE" -e "
      SELECT DATA_TYPE 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_NAME = '$table' AND COLUMN_NAME = '$column' AND TABLE_SCHEMA = '$DB_NAME_PRODCLONE';
    " | tail -n +2)  # Skipping header row
    
    case "$column_type" in
      "varchar"|"text"|"char")
        sanitize_text_columns $table $column
        ;;
      "int"|"bigint"|"decimal"|"float"|"double")
        sanitize_numeric_columns $table $column
        ;;
       "date")
        sanitize_date_columns $table $column
        ;;
      "enum")
        sanitize_enum_columns $table $column
        ;;
      "bit"|"tinyint")
        sanitize_binary_columns $table $column
        ;;
      *)
        echo "Unknown column type for $column in $table. Skipping sanitization."
        sanitize_null $table $column
        ;;
    esac
  done
}

# Function to sanitize specific columns in a table
sanitize_specific_columns() {
  for table in "${!columns_to_sanitize[@]}"; do
    columns=${columns_to_sanitize[$table]}
    
    # Split columns by comma and loop through each column
    IFS=',' read -ra column_array <<< "$columns"
    for column in "${column_array[@]}"; do
      # Check column type to decide which sanitization function to call
      column_type=$(mysql --defaults-file="$MY_CNF_FILE" -e "
        SELECT DATA_TYPE 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_NAME = '$table' AND COLUMN_NAME = '$column' AND TABLE_SCHEMA = '$DB_NAME_PRODCLONE';
      " | tail -n +2)  # Skipping header row
      
      case "$column_type" in
        "varchar"|"text"|"char")
          sanitize_text_columns $table $column
          ;;
        "int"|"bigint"|"decimal"|"float"|"double")
          sanitize_numeric_columns $table $column
          ;;
        "date")
         sanitize_date_columns $table $column
         ;;
        "enum")
          sanitize_enum_columns $table $column
          ;;
        "bit"|"tinyint")
          sanitize_binary_columns $table $column
          ;;
        *)
          echo "Unknown column type for $column in $table. Skipping sanitization."
          sanitize_timestamp_columns $table $column
          ;;
      esac
    done
  done
}

# Start sanitization of specified columns
sanitize_specific_columns

# Start sanitization of whole tables
for table in "${tables_to_sanitize_whole[@]}"; do
  sanitize_all_columns $table
done

echo "Data sanitization is complete."

# Delete the .my.cnf file
rm -f "$MY_CNF_FILE"
echo "MySQL credentials file (.my.cnf) has been deleted."
