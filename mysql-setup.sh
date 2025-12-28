#!/bin/bash

# Simple MySQL setup script for Replit
echo "Setting up MySQL database for Discord Bot..."

# Set environment variables if not already set
export DB_HOST=${DB_HOST:-localhost}
export DB_PORT=${DB_PORT:-3306}
export DB_USER=${DB_USER:-root}
export DB_PASSWORD=${DB_PASSWORD:-}
export DB_NAME=${DB_NAME:-discord_bot}

echo "Database configuration:"
echo "Host: $DB_HOST"
echo "Port: $DB_PORT"
echo "User: $DB_USER"
echo "Database: $DB_NAME"

# Initialize and run the database setup
echo "Running database initialization..."
node server/init-db.js

echo "MySQL setup completed!"
echo ""
echo "To use MySQL with your Discord bot:"
echo "1. Make sure MySQL is running on port 3306"
echo "2. Update your .env file with database credentials"
echo "3. Restart the bot with 'npm start'"