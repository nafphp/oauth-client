<?php

declare(strict_types=1);

namespace Tests;

/** What a command printed, and what it told the shell. */
final readonly class CommandResult
{
    public function __construct(
        public int $status,
        public string $output,
    ) {
    }

    /** One line per row, trimmed, so assertions do not depend on padding. */
    public function lines(): array
    {
        return array_values(array_filter(
            array_map(trim(...), explode(PHP_EOL, $this->output)),
            static fn(string $line): bool => $line !== '',
        ));
    }

    /** The first line mentioning this label, or null. */
    public function line(string $label): ?string
    {
        foreach ($this->lines() as $line) {
            if (str_contains($line, $label)) {
                return $line;
            }
        }

        return null;
    }

    /** The right-hand side of a padded "label   value" line. */
    public function value(string $label): string
    {
        $line = $this->line($label);

        return $line === null ? '' : trim((string) preg_replace('/^.*' . preg_quote($label, '/') . '\s*/', '', $line));
    }
}
