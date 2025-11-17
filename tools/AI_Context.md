# CLI-Security System - AI Context & Architecture Guide

## System Overview

**CLI-Security** is a PHP-based email security solution that integrates with Postfix, Dovecot, and Fail2Ban to provide comprehensive spam filtering and threat detection. The system is transitioning from host-based deployment to **container-first architecture** while maintaining host accessibility.

## Current Architecture Transition

### From: Host-Based Deployment
- Originally designed to run directly on host systems
- Installation path: `/opt/cyford/security`
- Direct system integration with Postfix/Dovecot
- Host-level permissions and sudoers configuration

### To: Container-First with Host Integration
- **Primary deployment**: Containerized mail stack
- **Host accessibility**: Container services exposed to host as if local
- **Persistent data**: Volumes for mail data, logs, and configuration
- **Network integration**: Host network access for mail services

## Core Components

### 1. **Main Application** (`index.php`)
- Entry point for all operations
- Handles multiple input types: `postfix`, `fail2ban`, `manual`, `internal`
- Bootstrap system loads dependencies and configuration

### 2. **Configuration System** (`config.php`)
- Environment-based configuration using `.env` files
- API integration settings (Cyford Web Armor)
- Postfix/Dovecot integration parameters
- Database and logging configuration
- Spam handling methods and thresholds

### 3. **Core Classes** (`src/Classes/`)
- **ApiClient**: Cyford Web Armor API integration
- **SpamFilter**: Local spam detection algorithms
- **Postfix**: Mail server integration and configuration
- **Database**: SQLite-based data persistence
- **Internal**: System management and setup commands
- **Fail2Ban**: Intrusion prevention integration
- **Systems**: OS detection and system operations

### 4. **Container Infrastructure**
- **Dockerfile**: Ubuntu-based with full mail stack
- **docker-compose.yml**: Service orchestration
- **docker-setup.sh**: Automated container configuration

## Key Features

### Email Security
- **Real-time spam filtering** via Postfix integration
- **Hash-based duplicate detection** for performance
- **X-Spam headers** for client-side filtering
- **Sieve rules** for automatic spam folder management
- **Multiple quarantine methods**: user maildir, system quarantine

### System Integration
- **Postfix content filtering** with chroot compatibility
- **Dovecot Sieve** for server-side email rules
- **Fail2Ban reporting** for IP threat intelligence
- **SquirrelMail** web interface for testing

### Container Features
- **Complete mail stack**: Postfix + Dovecot + SquirrelMail
- **Persistent storage** for mail data and logs
- **Port mapping**: Standard mail ports (25, 110, 143, 993, 995, 80)
- **Host integration**: Services accessible as if running locally

## Installation Paths & Structure

### Container Deployment (Primary)
```
/opt/cyford/security/          # Application code (mounted volume)
/var/mail/                     # Mail data (persistent volume)
/var/log/                      # Logs (persistent volume)
/var/spool/postfix/            # Postfix queue and chroot
/home/{user}/Maildir-cyford/   # User mailboxes
```

### Host Integration Points
```
localhost:25    # SMTP server
localhost:143   # IMAP server  
localhost:110   # POP3 server
localhost:8080  # SquirrelMail web interface
```

## Internal Commands System

The system includes comprehensive management commands via `--input_type=internal`:

### Setup Commands
- `setup-permissions`: Configure system permissions and sudoers
- `setup-database`: Initialize SQLite database with proper permissions
- `create-docker`: Generate complete Docker environment
- `setup-dovecot-sieve`: Configure server-side email filtering

### User Management
- `create-user`: Create mail users with system accounts and maildirs
- `setup-user-permissions`: Configure directory permissions for postfix access
- `setup-sieve-rules`: Deploy spam filtering rules for users

### Monitoring & Maintenance
- `stats`: System statistics and spam pattern analysis
- `view-spam-patterns`: Review detected spam patterns
- `test-spam-filter`: Test spam detection with sample content
- `system-inventory`: Complete system analysis

## Configuration Highlights

### Spam Handling Methods
```php
'spam_handling' => [
    'action' => 'quarantine',           # reject, quarantine, allow, headers
    'quarantine_method' => 'user_maildir', # user_maildir, system_quarantine
    'hash_detection' => true,           # Duplicate spam detection
    'threshold' => 70,                  # Spam detection threshold
]
```

### Container Integration
```php
'database' => [
    'path' => '/var/spool/postfix/cyford-security.db', # Chroot accessible
],
'task_queue' => [
    'queue_file' => '/var/spool/postfix/cyford-tasks.json', # Chroot accessible
],
```

## Development Workflow

### Container Development
1. `php index.php --input_type=internal --command=create-docker`
2. `docker-compose up -d`
3. `docker exec -it cyford-mail ./docker-setup.sh`
4. Create test users and test spam filtering

### Host Integration Testing
1. Verify port accessibility from host
2. Test SMTP/IMAP connectivity
3. Validate SquirrelMail web interface
4. Confirm mail delivery and spam filtering

## Key Technical Decisions

### Container-First Architecture
- **Rationale**: Easier deployment, consistent environment, better isolation
- **Host Integration**: Services exposed via port mapping for seamless host access
- **Data Persistence**: Critical data stored in named volumes

### SQLite Database
- **Location**: `/var/spool/postfix/` for chroot compatibility
- **Permissions**: Accessible to both postfix and report-ip users
- **Features**: Spam pattern storage, hash-based detection, statistics

### Spam Detection Strategy
- **Local-first**: Check local algorithms before API calls
- **Hash-based**: Duplicate detection for performance
- **Headers approach**: X-Spam headers for maximum compatibility
- **Sieve integration**: Server-side filtering rules

## Current Development Focus

### Container Optimization
- Streamline Docker image size and startup time
- Improve volume mounting for development workflow
- Enhance container health checks and monitoring

### Host Integration
- Ensure seamless host access to containerized services
- Maintain compatibility with existing host-based configurations
- Provide migration tools from host to container deployment

### Performance & Reliability
- Optimize spam detection algorithms
- Improve error handling and recovery
- Enhance logging and monitoring capabilities

## Usage Patterns

### Primary Use Cases
1. **Email Security**: Spam filtering and threat detection for mail servers
2. **Development Testing**: Container-based testing environment
3. **System Integration**: Fail2Ban and firewall integration
4. **Threat Intelligence**: IP reporting to Cyford Web Armor API

### Typical Workflows
1. **Setup**: Create Docker environment, configure services, create users
2. **Operation**: Monitor spam detection, review quarantined emails
3. **Maintenance**: Update spam patterns, review system statistics
4. **Integration**: Configure Fail2Ban reporting, firewall rules

## Technical Constraints

### Container Environment
- Must maintain chroot compatibility for Postfix
- Requires proper permission handling between container users
- Network configuration for host accessibility

### Host Integration
- Services must appear as local to host applications
- Configuration files may need host-side access
- Log files should be accessible from host

### Security Considerations
- Proper user separation between mail services
- Secure API communication with Cyford Web Armor
- Safe handling of email content and metadata

---

## AI Assistant Guidelines

When working with this system:

1. **Understand the container-first approach** - Primary deployment is containerized
2. **Maintain host compatibility** - Services should be accessible as if running locally  
3. **Respect the permission model** - Complex user/group permissions for mail services
4. **Consider chroot limitations** - Postfix runs in chroot, affects file paths
5. **Use internal commands** - Leverage the comprehensive internal command system
6. **Test in container environment** - Use Docker setup for development and testing

The system is designed for production email security while providing a complete development environment through containerization.