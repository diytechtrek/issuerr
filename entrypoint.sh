#!/bin/bash
set -e

# Get PUID and PGID from environment variables, default to 1000
PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Validate PUID is a positive integer between 1-65535
if ! [[ "$PUID" =~ ^[0-9]+$ ]]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: PUID must be a positive integer"
    echo "   Received: '$PUID'"
    echo "   Example: PUID=1000"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

if [ "$PUID" -lt 1 ] || [ "$PUID" -gt 65535 ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: PUID must be between 1 and 65535"
    echo "   Received: $PUID"
    echo "   Valid range: 1-65535"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

# Validate PGID is a positive integer between 1-65535
if ! [[ "$PGID" =~ ^[0-9]+$ ]]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: PGID must be a positive integer"
    echo "   Received: '$PGID'"
    echo "   Example: PGID=1000"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

if [ "$PGID" -lt 1 ] || [ "$PGID" -gt 65535 ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: PGID must be between 1 and 65535"
    echo "   Received: $PGID"
    echo "   Valid range: 1-65535"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

# Explicitly prevent running as root for security
if [ "$PUID" -eq 0 ] || [ "$PGID" -eq 0 ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: Running as root (UID/GID 0) is not allowed"
    echo "   This is a security restriction to prevent privilege escalation."
    echo "   "
    echo "   Received: PUID=$PUID, PGID=$PGID"
    echo "   Solution: Use PUID and PGID values of 1 or higher"
    echo "   Default:  PUID=1000, PGID=1000"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

echo "────────────────────────────────────────────────────"
echo "  _                                "
echo " (_)___ ___ _   _  ___ _ __ _ __  "
echo " | / __/ __| | | |/ _ \ '__| '__| "
echo " | \__ \__ \ |_| |  __/ |  | |    "
echo " |_|___/___/\__,_|\___|_|  |_|    "
echo "                                   "
echo "────────────────────────────────────────────────────"
echo "✓ PUID/PGID validation passed"
echo "  Starting Issuerr with UID:GID $PUID:$PGID"
echo "────────────────────────────────────────────────────"

# Check if we're running as root (we should be for initialization)
if [ "$(id -u)" = "0" ]; then
    echo "Running as root - setting up permissions..."
    
    # Create appuser if it doesn't exist with specified PUID/PGID
    if ! id -u appuser >/dev/null 2>&1; then
        echo "Creating appuser with UID:GID $PUID:$PGID"
        groupadd -g "$PGID" appuser 2>/dev/null || true
        useradd -u "$PUID" -g "$PGID" -m -s /bin/bash appuser 2>/dev/null || true
    else
        echo "appuser already exists"
        # Modify existing user to match PUID/PGID if different
        CURRENT_UID=$(id -u appuser)
        CURRENT_GID=$(id -g appuser)
        
        if [ "$CURRENT_UID" != "$PUID" ] || [ "$CURRENT_GID" != "$PGID" ]; then
            echo "Updating appuser UID from $CURRENT_UID to $PUID"
            echo "Updating appuser GID from $CURRENT_GID to $PGID"
            groupmod -g "$PGID" appuser 2>/dev/null || true
            usermod -u "$PUID" -g "$PGID" appuser 2>/dev/null || true
        fi
    fi
    
    # Ensure config directory exists
    mkdir -p /config /config/logs
    
    # Set ownership of config directory to appuser
    echo "Setting ownership of /config to $PUID:$PGID"
    chown -R "$PUID:$PGID" /config
    
    # Set ownership of app directory to appuser
    chown -R "$PUID:$PGID" /app
    
    echo "Permissions set successfully"
    echo "────────────────────────────────────────────────────"
    
    # Drop privileges and execute command as appuser
    exec gosu "$PUID:$PGID" "$@"
else
    # Already running as non-root user, just execute
    echo "Already running as non-root user"
    echo "────────────────────────────────────────────────────"
    exec "$@"
fi
