<?php

class CommandLineArguments
{
    private array $arguments;
    private string $inputType; // New property to store input type

    public function __construct(array $argv)
    {
        // Ensure the script is running in CLI mode
        if (php_sapi_name() !== 'cli') {
            throw new RuntimeException("This script must be run from the command line.");
        }

        // Parse arguments, excluding the script name ($argv[0])
        $this->arguments = $this->parseArguments(array_slice($argv, 1));

        // Automatically determine and validate the input_type
        $this->inputType = $this->determineInputType();
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
     * Automatically determine the input_type and validate it.
     *
     * @return string The valid input type (e.g., 'postfix', 'fail2ban', 'manual')
     * @throws RuntimeException if the input_type is invalid or not provided
     */
    private function determineInputType(): string
    {
        $inputType = $this->arguments['input_type'] ?? null;

        if (!$inputType) {
            throw new RuntimeException("Missing required argument: --input_type");
        }

        // Validate the input type
        $validInputTypes = ['postfix', 'fail2ban', 'manual'];
        if (!in_array($inputType, $validInputTypes, true)) {
            throw new RuntimeException("Invalid input_type provided: {$inputType}. Valid options are: " . implode(', ', $validInputTypes));
        }

        return $inputType;
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
     * Get a specific input type (postfix, fail2ban, manual).
     *
     * @return string
     */
    public function getInputType(): string
    {
        return $this->inputType;
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