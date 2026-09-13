<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Account;

/**
 * One external identity, attached to one local account.
 *
 * Both halves are two-part. Outside, an identity is `(issuer, subject)` because a
 * subject is only ever unique within its issuer. Inside, an account is
 * `(userProvider, userId)` because nixphp/auth allows several account sources and
 * their ids can collide — the same pair the session stores.
 */
final readonly class AccountLink
{
    public function __construct(
        public string $provider,
        public string $issuer,
        public string $subject,
        public string $userProvider,
        public string $userId,
    ) {}
}
