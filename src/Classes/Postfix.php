<?php

class Postfix
{
    private string $postfixCommand;

    public function __construct(string $postfixPath = '/usr/sbin/postfix')
    {
        $this->postfixCommand = $postfixPath;

        if (!file_exists($this->postfixCommand)) {
            throw new RuntimeException("Postfix command not found at: {$this->postfixCommand}");
        }
    }

    /**
     * Reload Postfix
     *
     * @return void
     * @throws RuntimeException
     */
    public function reload(): void
    {
        $command = "{$this->postfixCommand} reload";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to reload Postfix.');
        }
    }

    /**
     * Get Postfix status
     *
     * @return string Postfix status output
     * @throws RuntimeException
     */
    public function getStatus(): string
    {
        $command = "systemctl status postfix";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to retrieve Postfix status.');
        }

        return $output;
    }

    /**
     * Start Postfix
     *
     * @return void
     * @throws RuntimeException
     */
    public function start(): void
    {
        $command = "{$this->postfixCommand} start";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to start Postfix.');
        }
    }

    /**
     * Stop Postfix
     *
     * @return void
     * @throws RuntimeException
     */
    public function stop(): void
    {
        $command = "{$this->postfixCommand} stop";
        $output = shell_exec($command);

        if (!$output) {
            throw new RuntimeException('Failed to stop Postfix.');
        }
    }
}