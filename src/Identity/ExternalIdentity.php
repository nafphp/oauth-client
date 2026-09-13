<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Identity;

/**
 * Somebody a provider has vouched for, and nothing more.
 *
 * This is not a user of your application: it is the verified answer to "who does
 * the provider say this is". Turning it into one of your accounts is the single
 * decision this plugin will not make for you.
 *
 * `issuer` and `subject` together are the stable key. A subject is only ever
 * unique within its issuer, so neither half is a key on its own.
 */
final readonly class ExternalIdentity
{
    /** @param array<string,mixed> $claims */
    public function __construct(
        public string $provider,
        public string $issuer,
        public string $subject,
        public array $claims = [],
        public ?string $email = null,
        public bool $emailVerified = false,
        public ?string $name = null,
    ) {}

    public function claim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }
}
