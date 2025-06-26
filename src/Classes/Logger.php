<?php
namespace Cyford\Security\Classes;

class Logger
{
    private string $logFilePath;
    private string $errorLogFilePath;

    public function __construct(array $config)
    {
        // Get general log file path and error log path from config
        $defaultBasePath = '/tmp/cyford-security'; // Fallback path if provided paths are not writable
        $logPath = $config['log']['file_path'] ?? "$defaultBasePath/application.log";
        $errorLogPath = $config['errors']['error_log_location'] ?? "$defaultBasePath/errors/error.log";

        // Validate or fallback to writable paths
        $this->logFilePath = $this->validatePath($logPath, "$defaultBasePath/application.log");
        $this->errorLogFilePath = $this->validatePath($errorLogPath, "$defaultBasePath/errors/error.log");

        // Ensure directory structure for writable paths
        $this->ensureDirectory(dirname($this->logFilePath));
        $this->ensureDirectory(dirname($this->errorLogFilePath));
    }

    /**
     * Ensure the directory exists, and create it if it does not.
     *
     * @param string $directory
     * @return void
     */
    private function ensureDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0755, true) && !is_dir($directory)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $directory));
            }
        }
    }

    /**
     * Validate file path and ensure it is writable.
     * Falls back to a default file path if validation fails.
     *
     * @param string $path
     * @param string $fallbackPath
     * @return string
     */
    private function validatePath(string $path, string $fallbackPath): string
    {
        $dir = dirname($path);

        // Check if the directory is writable
        if (!is_dir($dir) || !is_writable($dir)) {
            $this->ensureDirectory(dirname($fallbackPath));
            return $fallbackPath;
        }

        return $path;
    }

    /**
     * Log a generic message.
     *
     * @param string $level E.g., INFO, WARNING, ERROR.
     * @param string $message Log details.
     * @param bool $isErrorLog Log to the error log file.
     * @return void
     */
    public function log(string $level, string $message, bool $isErrorLog = false): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[{$timestamp}] {$level}: {$message}" . PHP_EOL;

        $filePath = $isErrorLog ? $this->errorLogFilePath : $this->logFilePath;

        try {
            file_put_contents($filePath, $logMessage, FILE_APPEND);
        } catch (\Exception $e) {
            // Fallback: Write to STDERR
            fwrite(STDERR, "[Logger Error] Failed to write log: {$e->getMessage()}" . PHP_EOL);
        }
    }

    /**
     * Log informational messages.
     *
     * @param string $message
     * @return void
     */
    public function info(string $message): void
    {
        $this->log('INFO', $message);
    }

    /**
     * Log warnings.
     *
     * @param string $message
     * @return void
     */
    public function warning(string $message): void
    {
        $this->log('WARNING', $message);
    }

    /**
     * Log errors. Redirects to the error log file.
     *
     * @param string $message
     * @return void
     */
    public function error(string $message): void
    {
        $this->log('ERROR', $message, true);
    }
}