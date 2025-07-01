# Cyford Security System Organization Chart

## Process Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SYSTEM INITIALIZATION                             │
│                     Command: --system-inventory                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. SYSTEM.PHP CLASS - System Discovery                                     │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │ • Create JSON/Array of installed software                          │  │
│    │ • OS Specifications: type, CPUs, memory, disk space               │  │
│    │ • Network: public IP, interfaces                                  │  │
│    │ • Triggered only by internal command                              │  │
│    └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. CONFIG.PHP IMPORT                                                       │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │ • Load all configuration settings                                  │  │
│    │ • Application enable/disable flags                                 │  │
│    │ • Backup directories and paths                                     │  │
│    └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. APPLICATION PROCESSING LOGIC                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
┌─────────────────────────────────┐    ┌─────────────────────────────────┐
│ SOFTWARE INSTALLED?             │    │ SOFTWARE NOT INSTALLED?         │
│ CONFIG ENABLED?                 │    │                                 │
└─────────────────────────────────┘    └─────────────────────────────────┘
                    │                                   │
                    ▼                                   ▼
┌─────────────────────────────────┐    ┌─────────────────────────────────┐
│ 4A. ENABLED PATH                │    │ 4B. DISABLED PATH               │
│ ┌─────────────────────────────┐ │    │ ┌─────────────────────────────┐ │
│ │ • Create backup directory   │ │    │ │ • Mark as disabled in JSON  │ │
│ │   /backup/[app_name]/       │ │    │ │ • Skip processing           │ │
│ │ • Backup config files       │ │    │ │                             │ │
│ │ • Proceed to step 5         │ │    │ └─────────────────────────────┘ │
│ └─────────────────────────────┘ │    └─────────────────────────────────┘
└─────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. POSTFIX CONFIGURATION ANALYSIS                                          │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │ • Parse existing Postfix configuration                             │  │
│    │ • Determine setup type:                                            │  │
│    │   ├─ Fresh installation (default configs)                         │  │
│    │   └─ Custom/tailored setup (modified configs)                     │  │
│    │ • Generate compatibility report                                    │  │
│    └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. INTEGRATION DECISION TREE                                               │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │ Fresh Setup:                                                       │  │
│    │ • Apply standard Cyford configuration                              │  │
│    │ • Enable security filters                                          │  │
│    │                                                                    │  │
│    │ Custom Setup:                                                      │  │
│    │ • Preserve existing configuration                                  │  │
│    │ • Integrate security filters carefully                             │  │
│    │ • Generate migration plan                                          │  │
│    └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Structure

```json
{
  "system_info": {
    "os": { "type": "linux", "version": "ubuntu-20.04" },
    "hardware": {
      "cpu_count": 4,
      "memory_total": "8GB",
      "memory_free": "2GB",
      "disk_total": "100GB",
      "disk_free": "50GB"
    },
    "network": {
      "public_ip": "1.2.3.4",
      "interfaces": {
        "eth0": "192.168.1.100",
        "eth1": "10.0.0.5",
        "lo": "127.0.0.1"
      }
    }
  },
  "applications": {
    "postfix": {
      "installed": true,
      "enabled": true,
      "backup_path": "./backup/postfix/",
      "config_type": "custom|fresh",
      "status": "ready|disabled|error"
    }
  }
}
```