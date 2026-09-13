<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Account;

use NixPHP\OAuth\Client\Identity\ExternalIdentity;

/** Which local account an external identity belongs to. */
interface AccountLinkStoreInterface
{
    public function find(string $issuer, string $subject): ?AccountLink;

    /** @throws \NixPHP\OAuth\Client\Exception\OAuthException when it already belongs to somebody. */
    public function link(ExternalIdentity $identity, string $userProvider, string $userId): AccountLink;

    public function unlink(string $issuer, string $subject): void;

    /** @return list<AccountLink> Every provider this account can sign in with. */
    public function forAccount(string $userProvider, string $userId): array;

    /**
     * Run this as one unit of work.
     *
     * Creating an account and linking it are one act with two halves; if the
     * second fails, the first has to go too. Otherwise a failed first login
     * leaves an account nothing points at, and the next attempt makes another.
     *
     * @template T
     * @param callable(): T $work
     * @return T
     */
    public function transaction(callable $work): mixed;
}
