<?php

class CommandLineArguments
{
    private array $arguments;

    public function __construct(array $argv)
    {
        // Ensure the script is running in CLI mode
        if (php_sapi_name() !== 'cli') {
            throw new RuntimeException("This script must be run from the command line.");
        }

        // Parse arguments, excluding the script name ($argv[0])
        $this->arguments = $this->parseArguments(array_slice($argv, 1));
    }

    /**
     * Parse named arguments from the given array (e.g., "--key=value")
     *
     * @param array $arguments
     * @return array
     */
    private function parseArguments(array $arguments): array
    {
        $parsedArgs = [];
        foreach ($arguments as $arg) {
            if (str_starts_with($arg, '--')) {
                $arg = ltrim($arg, '--');
                if (strpos($arg, '=') !== false) {
                    [$key, $value] = explode('=', $arg, 2);
                    $parsedArgs[$key] = $value;
                } else {
                    $parsedArgs[$arg] = true; // Flag without value
                }
            }
        }
        return $parsedArgs;
    }

    /**
     * Get all parsed arguments.
     *
     * @return array
     */
    public function getAll(): array
    {
        return $this->arguments;
    }

    /**
     * Get a specific argument by key, with an optional default value.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed|null
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->arguments[$key] ?? $default;
    }

    /**
     * Check if a flag exists (boolean arguments like `--flag`).
     *
     * @param string $key
     * @return bool
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->arguments);
    }
}