#!/bin/bash

# Create MySQL data directory
mkdir -p /tmp/mysql_data

# Initialize MySQL database if not already done
if [ ! -d "/tmp/mysql_data/mysql" ]; then
    echo "Initializing MySQL database..."
    mysqld --initialize-insecure --user=$(whoami) --datadir=/tmp/mysql_data
fi

# Start MySQL server
echo "Starting MySQL server..."
mysqld --user=$(whoami) --datadir=/tmp/mysql_data --socket=/tmp/mysql.sock --port=3306 --bind-address=0.0.0.0 --skip-networking=false

echo "MySQL server started on port 3306"