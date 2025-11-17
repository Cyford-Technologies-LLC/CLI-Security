#!/bin/bash
echo "🚀 Initializing Cyford Security Live System..."

# Change to application directory
cd /opt/cyford/security

# Setup permissions
echo "📋 Setting up permissions..."
php index.php --input_type=internal --command=setup-permissions

# Setup database
echo "🗄️ Setting up database..."
php index.php --input_type=internal --command=setup-database

# Test host system access
echo "🔍 Testing host system access..."

# Test Docker access
if command -v docker >/dev/null 2>&1; then
    echo "✅ Docker CLI available"
    if docker ps >/dev/null 2>&1; then
        echo "✅ Docker socket accessible"
        echo "📋 Running containers:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | head -5
    else
        echo "❌ Docker socket not accessible"
    fi
else
    echo "❌ Docker CLI not accessible"
fi

# Test firewalld access
if command -v firewall-cmd >/dev/null 2>&1; then
    echo "✅ Firewalld access available"
    firewall-cmd --state 2>/dev/null && echo "✅ Firewalld is running" || echo "⚠️ Firewalld not running"
else
    echo "❌ Firewalld not accessible"
fi

# Test fail2ban access
if command -v fail2ban-client >/dev/null 2>&1; then
    echo "✅ Fail2Ban access available"
    fail2ban-client status 2>/dev/null && echo "✅ Fail2Ban is running" || echo "⚠️ Fail2Ban not running"
else
    echo "❌ Fail2Ban not accessible"
fi

# Test Postfix integration
echo "📧 Testing Postfix integration..."
if [ -d "/var/spool/postfix" ]; then
    echo "✅ Postfix spool directory accessible"
    ls -la /var/spool/postfix/ | head -5
else
    echo "❌ Postfix spool directory not accessible"
fi

# Setup Fail2Ban integration
echo "🛡️ Setting up Fail2Ban integration..."
php index.php --input_type=internal --command=setup-fail2ban

echo "✅ Live system initialization completed!"
echo ""
echo "🔧 System Status:"
echo "  - Database: Initialized"
echo "  - Permissions: Configured"
echo "  - Host Integration: Active"
echo "  - Firewalld: $(command -v firewall-cmd >/dev/null && echo 'Available' || echo 'Not Available')"
echo "  - Fail2Ban: $(command -v fail2ban-client >/dev/null && echo 'Available' || echo 'Not Available')"
echo ""
echo "📋 Available Commands:"
echo "  php index.php --input_type=internal --command=stats"
echo "  php index.php --input_type=internal --command=report-jailed-ips"
echo "  php index.php --input_type=internal --command=system-inventory"

# Keep container running
echo "🔄 Starting monitoring loop..."
while true; do
    # Process any queued tasks
    if [ -f "/var/spool/cyford-security/tasks.json" ]; then
        php index.php --input_type=internal --command=queue-status >/dev/null 2>&1
    fi
    sleep 60
done