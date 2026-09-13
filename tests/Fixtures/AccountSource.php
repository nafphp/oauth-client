<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use Naf\Auth\Credentials\CredentialsInterface;
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Provider\ProviderInterface;

/**
 * A local account source.
 *
 * find() honours the suspended flag, which is what makes a locked account a guest
 * again: reloading alone does not do it, the source has to say so.
 */
final class AccountSource implements ProviderInterface
{
    /** @var array<string, Account> */
    public array $accounts = [];

    public function add(Account $account): Account
    {
        return $this->accounts[$account->getIdentifier()] = $account;
    }

    public function find(string $identifier): ?IdentityInterface
    {
        $account = $this->accounts[$identifier] ?? null;

        return $account?->active === true ? $account : null;
    }

    public function authenticate(#[\SensitiveParameter] CredentialsInterface $credentials): ?IdentityInterface
    {
        return null;
    }
}
