<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use Naf\OAuth\Client\Core\TransactionStoreInterface;

/** The session store's behaviour without a session: keyed by state, taken once. */
final class ArrayTransactions implements TransactionStoreInterface
{
    /** @var array<string, array<string, mixed>> */
    public array $pending = [];

    public function put(string $state, array $data): void
    {
        $this->pending[$state] = $data;
    }

    public function take(string $state): ?array
    {
        $entry = $this->pending[$state] ?? null;
        unset($this->pending[$state]);

        return $entry;
    }
}
