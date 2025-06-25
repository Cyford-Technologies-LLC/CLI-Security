<?php
$backupDirectory = '/var/backups/postfix';
$mainConfigPath = '/etc/postfix/main.cf';
$masterConfigPath = '/etc/postfix/master.cf';

function backupFile(string $filePath, string $backupDirectory): void {
    if (!file_exists($filePath)) {
        throw new RuntimeException("File not found for backup: {$filePath}");
    }

    $timestamp = date('Ymd_His');
    $fileName = basename($filePath);
    $backupPath = "{$backupDirectory}/{$fileName}.backup_{$timestamp}";

    if (!copy($filePath, $backupPath)) {
        throw new RuntimeException("Failed to create backup for: {$filePath}");
    }

    echo "Backup created: {$backupPath}\n";
}

// Test main.cf backup
backupFile($mainConfigPath, $backupDirectory);

// Test master.cf backup
backupFile($masterConfigPath, $backupDirectory);