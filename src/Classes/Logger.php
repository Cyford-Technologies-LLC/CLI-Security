<?php
namespace Cyford\Security\Classes;
namespace Cyford\Security\Classes;


class Logger
{
    private string $logFilePath;
    private string $errorLogFilePath;

    public function __construct(array $config)
    {
        // Get general log file path and error log path from config
        $this->logFilePath = $config['log']['file_path'] ?? BASE_PATH . '/logs/application.log';
        $this->errorLogFilePath = $config['errors']['error_log_location'] ?? BASE_PATH . '/logs/errors/error.log';

        // Ensure the log directory exists
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
            mkdir($directory, 0755, true);
        }
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
        file_put_contents($filePath, $logMessage, FILE_APPEND);
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