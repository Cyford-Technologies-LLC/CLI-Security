# System Inventory Command

## Internal Command
```bash
php index.php --system-inventory
```

## Function: performSystemInventory()

### Process:
1. **Software Detection**
   - Check for postfix, apache, nginx, dovecot, etc.
   - Get version numbers and installation paths

2. **System Specifications**
   - OS type, version, architecture
   - CPU count and model
   - Memory total/free
   - Disk space total/free

3. **Network Information**
   - Public IP from external source
   - All interface IPs (eth0, eth1, lo, etc.)

4. **Output**
   - Save to `./system_inventory.json`
   - Return array for immediate use

### JSON Structure:
```json
{
  "timestamp": "2025-01-02 12:00:00",
  "system": {
    "os": "Ubuntu 20.04",
    "arch": "x86_64",
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
  },
  "software": {
    "postfix": {
      "installed": true,
      "version": "3.4.13",
      "config_path": "/etc/postfix/"
    }
  }
}
```