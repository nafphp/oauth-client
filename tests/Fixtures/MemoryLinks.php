<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use NixPHP\OAuth\Client\Account\AccountLink;
use NixPHP\OAuth\Client\Account\AccountLinkStoreInterface;
use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Identity\ExternalIdentity;

/** The PDO store's behaviour without a database, including its uniqueness. */
final class MemoryLinks implements AccountLinkStoreInterface
{
    /** @var array<string, AccountLink> */
    public array $links = [];

    public function find(string $issuer, string $subject): ?AccountLink
    {
        return $this->links[$issuer . "\0" . $subject] ?? null;
    }

    public function link(ExternalIdentity $identity, string $userProvider, string $userId): AccountLink
    {
        $key = $identity->issuer . "\0" . $identity->subject;

        if (isset($this->links[$key])) {
            throw OAuthException::of('already_linked', 'That provider account is already linked.');
        }

        return $this->links[$key] = new AccountLink(
            $identity->provider,
            $identity->issuer,
            $identity->subject,
            $userProvider,
            $userId,
        );
    }

    public function unlink(string $issuer, string $subject): void
    {
        unset($this->links[$issuer . "\0" . $subject]);
    }

    public function transaction(callable $work): mixed
    {
        // No database, nothing to roll back — the point of this fixture is that
        // the caller behaves the same either way.
        return $work();
    }

    public function forAccount(string $userProvider, string $userId): array
    {
        return array_values(array_filter(
            $this->links,
            static fn(AccountLink $link): bool => $link->userProvider === $userProvider && $link->userId === $userId,
        ));
    }
}
