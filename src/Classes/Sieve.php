<?php
namespace Cyford\Security\Classes;

class Sieve
{
    private array $config;
    private Systems $systems;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->systems = new Systems();
    }

    /**
     * Setup Sieve rules for spam filtering
     */
    public function setupSieveRules(string $username): void
    {
        if (empty($username)) {
            echo "❌ Username is required\n";
            echo "Usage: --command=setup-sieve-rules --username=allen\n";
            echo "       --command=setup-sieve-rules --username=all\n";
            return;
        }
        
        // Check and install Dovecot Sieve requirements first
        if (!$this->checkAndInstallSieveRequirements()) {
            echo "❌ Failed to install Sieve requirements\n";
            return;
        }
        
        if ($username === 'all') {
            $this->setupSieveRulesForAllUsers();
            return;
        }
        
        echo "📧 Setting up Sieve spam filtering rules for: {$username}\n";
        
        try {
            $this->setupSingleUserSieveRules($username);
            echo "\n🎉 Sieve rules setup completed for {$username}!\n";
        } catch (Exception $e) {
            echo "❌ Sieve rules setup failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Complete Dovecot Sieve setup
     */
    public function setupDovecotSieve(): void
    {
        echo "🚀 Starting complete Dovecot Sieve setup...\n";
        
        $osInfo = $this->systems->getOSInfo();
        echo "🔍 Detected OS: {$osInfo['os']}\n";
        
        $allowModification = $this->config['postfix']['allow_modification'] ?? false;
        if (!$allowModification) {
            echo "❌ Auto-configuration disabled. Set 'allow_modification' => true in config.php\n";
            return;
        }
        
        try {
            // 1. Check/Install Dovecot
            echo "\n📦 Step 1: Installing Dovecot and Sieve...\n";
            $this->installDovecotAndSieve();
            
            // 2. Configure Dovecot Sieve
            echo "\n⚙️  Step 2: Configuring Dovecot Sieve...\n";
            $this->configureDovecotSieve();
            
            // 3. Setup permissions
            echo "\n🔒 Step 3: Setting up permissions...\n";
            $this->setupDovecotPermissions();
            
            echo "\n🎉 Dovecot Sieve setup completed successfully!\n";
            echo "\n📝 Next steps:\n";
            echo "  1. Run: --command=setup-sieve-rules --username=all\n";
            echo "  2. Test spam filtering\n";
            
        } catch (Exception $e) {
            echo "❌ Setup failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Fix Dovecot permission issues
     */
    public function fixDovecotPermissions(): void
    {
        echo "🔧 Aggressively fixing all Dovecot permission issues...\n";
        
        // Stop dovecot first
        exec('systemctl stop dovecot 2>/dev/null');
        echo "⏹️  Stopped Dovecot\n";
        
        // Fix all log files and directories
        $commands = [
            'mkdir -p /var/log/dovecot /var/log/dovcot',
            'touch /var/log/dovecot/error.log /var/log/dovcot/error.log',
            'touch /var/log/dovecot/info.log /var/log/dovcot/info.log',
            'chown -R dovecot:mail /var/log/dovecot /var/log/dovcot',
            'chmod -R 777 /var/log/dovecot /var/log/dovcot',
        ];
        
        foreach ($commands as $cmd) {
            exec($cmd . ' 2>/dev/null');
        }
        echo "✅ Fixed all log file permissions (777)\n";
        
        // Start dovecot
        exec('systemctl start dovecot 2>/dev/null');
        echo "▶️  Started Dovecot\n";
        
        echo "\n🎉 Aggressive permission fix completed!\n";
    }

    // Private helper methods would go here...
    // (All the existing Sieve-related private methods from Internal.php)
}