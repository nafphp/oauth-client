<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Core;

/**
 * Where a login keeps what its callback will need.
 *
 * Entries are keyed by their own `state`, so several logins can be in flight at
 * once — a person with three tabs open finishes all three. Taking an entry
 * consumes it: a replayed callback finds nothing.
 */
interface TransactionStoreInterface
{
    /** @param array<string, mixed> $data */
    public function put(string $state, array $data): void;

    /** @return array<string, mixed>|null Null once it is used, expired or never existed. */
    public function take(string $state): ?array;
}
