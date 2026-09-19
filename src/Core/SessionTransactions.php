<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Core;

use Naf\OAuth\Client\Exception\OAuthException;
use Naf\Session\Core\Session;

/**
 * Pending logins, kept in the naf/session session.
 *
 * The session is what binds a login to one browser: without it, a `state` proves
 * nothing and the whole exchange is decoration. So a missing session aborts the
 * login instead of quietly continuing with a weaker one.
 *
 * **A known limit.** Taking an entry is read-modify-write, and what makes that
 * indivisible is the session backend holding a lock for the request. PHP's own
 * file handler does; naf/session's database handler does not. Two callbacks
 * arriving for the same state in the same instant could therefore both find it
 * there. Every check after that still applies — the code is single-use at the
 * provider, and the ID token still has to verify — so this is a narrowing of the
 * replay guarantee rather than a way through it. A locking session backend
 * closes it.
 */
final class SessionTransactions implements TransactionStoreInterface
{
    public function __construct(
        private readonly Session $session,
        private readonly string $key = 'oauth',
        private readonly int $ttl = 600,
        private readonly int $limit = 5,
    ) {
    }

    public function put(string $state, array $data): void
    {
        $this->session->start();

        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw OAuthException::of(
                'no_session',
                'A browser login needs an active session. Install naf/session and let it start.',
            );
        }

        $pending         = $this->pending();
        $pending[$state] = ['at' => time()] + $data;

        // Oldest out first: somebody who opens a sixth tab loses their first
        // attempt, not their latest one.
        if (count($pending) > $this->limit) {
            $pending = array_slice($pending, -$this->limit, null, true);
        }

        $this->session->set($this->key, $pending);
    }

    public function take(string $state): ?array
    {
        $pending = $this->pending();
        $entry   = $pending[$state] ?? null;

        unset($pending[$state]);
        $this->session->set($this->key, $pending);

        return is_array($entry) ? $entry : null;
    }

    /** @return array<string, array<string, mixed>> */
    private function pending(): array
    {
        $stored = $this->session->get($this->key);

        if (!is_array($stored)) {
            return [];
        }

        $now   = time();
        $alive = [];

        foreach ($stored as $state => $entry) {
            if (is_string($state) && is_array($entry)
                && is_int($entry['at'] ?? null) && $now - $entry['at'] <= $this->ttl) {
                $alive[$state] = $entry;
            }
        }

        return $alive;
    }
}
