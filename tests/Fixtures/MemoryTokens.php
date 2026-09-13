<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use NixPHP\OAuth\Client\Token\ProviderToken;
use NixPHP\OAuth\Client\Token\TokenStoreInterface;

/** The PDO store's behaviour without a database, encryption aside. */
final class MemoryTokens implements TokenStoreInterface
{
    /** @var array<string, ProviderToken> */
    public array $tokens = [];

    public function find(string $issuer, string $subject): ?ProviderToken
    {
        return $this->tokens[$issuer . "\0" . $subject] ?? null;
    }

    public function put(ProviderToken $token): void
    {
        $this->tokens[$token->issuer . "\0" . $token->subject] = $token;
    }

    public function forget(string $issuer, string $subject): void
    {
        unset($this->tokens[$issuer . "\0" . $subject]);
    }
}
