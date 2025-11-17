# Cyford Security Docker Systems

## Overview

This directory contains two Docker deployment configurations:

- **`testing/`** - Complete mail stack for development and testing
- **`live/`** - Production system with host integration

## Testing System (`testing/`)

**Purpose**: Development and testing with complete mail stack

**Includes**:
- Postfix (SMTP server)
- Dovecot (IMAP/POP3 server)
- SquirrelMail (Web interface)
- Cyford Security integration

**Usage**:
```bash
cd system/testing
docker-compose up -d
docker exec -it cyford-mail ./docker-setup.sh
```

**Access**:
- SMTP: localhost:25
- IMAP: localhost:143
- POP3: localhost:110
- Web: http://localhost:8081/webmail

## Live System (`live/`)

**Purpose**: Production deployment with host system integration

**Features**:
- Host firewalld control
- Host fail2ban integration
- External Postfix container connection
- System monitoring and reporting

**Usage**:
```bash
cd system/live
docker-compose up -d
```

**Host Integration**:
- Firewalld: Direct host access via mounted binaries
- Fail2Ban: Host service integration
- Postfix: External container communication
- Logs: Host log directory access

## Key Differences

| Feature | Testing | Live |
|---------|---------|------|
| Mail Stack | Included | External |
| Host Access | Limited | Full |
| Firewalld | No | Yes |
| Fail2Ban | No | Yes |
| Purpose | Development | Production |

## Configuration

Both systems use the same application code from the project root (`../../`) but with different integration approaches:

- **Testing**: Self-contained mail environment
- **Live**: Host system integration with external services