<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Core;

use NixPHP\OAuth\Client\Exception\OAuthException;
use Nyholm\Psr7\Request;
use Psr\Http\Client\ClientInterface;
use Throwable;

/**
 * Discovery documents and signing keys, fetched rarely and kept on disk.
 *
 * Providers rotate their signing keys on their own schedule, so the keys cannot
 * be configuration. They also cannot be fetched per request. This sits in
 * between: a long time-to-live, plus one forced refresh when a token arrives
 * signed with a key we have not seen — which is exactly what a rotation looks
 * like from here. The forced path has a cooldown, so a stream of tokens carrying
 * invented key ids cannot turn into a stream of outbound requests.
 *
 * A failed refresh falls back to what is already cached. It never falls back to
 * "no keys": that would turn an unreachable provider into an unverified login.
 */
final class Metadata
{
    public function __construct(
        private readonly ClientInterface $http,
        private readonly string $path,
        private readonly int $ttl = 86400,
        private readonly int $refreshCooldown = 300,

        // How long stale metadata may still be used once the provider stops
        // answering. Past this, a login fails with something a person can act on
        // rather than quietly relying on a day-old key set forever.
        private readonly int $graceAfterExpiry = 86400,
    ) {}

    /** @return array<string, mixed> */
    public function document(string $url): array
    {
        return $this->cached($url, false);
    }

    /** @return array<string, mixed> */
    public function jwks(string $url, bool $refresh = false): array
    {
        return $this->cached($url, $refresh);
    }

    /** @return array<string, mixed> */
    private function cached(string $url, bool $refresh): array
    {
        $file  = $this->path . '/' . hash('sha256', $url) . '.json';
        $entry = $this->read($file);
        $now   = time();

        if ($entry !== null) {
            $age = $now - (int) ($entry['at'] ?? 0);

            if (!$refresh && $age < $this->ttl) {
                return $entry['data'];
            }

            if ($refresh && $now - (int) ($entry['forced_at'] ?? 0) < $this->refreshCooldown) {
                return $entry['data'];
            }

            // A provider that is down stays down for a while. Without this, every
            // login turns into another outbound request to something not answering.
            if ($now - (int) ($entry['failed_at'] ?? 0) < $this->refreshCooldown) {
                return $this->stale($entry, $url, $now);
            }
        }

        try {
            $data = $this->fetch($url);
        } catch (Throwable $e) {
            if ($entry !== null) {
                $this->write($file, ['failed_at' => $now] + $entry);

                return $this->stale($entry, $url, $now, $e);
            }

            throw OAuthException::of('metadata_unavailable', 'Could not read ' . $url . '.', $e);
        }

        $this->write($file, [
            'at'        => $now,
            'forced_at' => $refresh ? $now : (int) ($entry['forced_at'] ?? 0),
            'data'      => $data,
        ]);

        return $data;
    }

    /**
     * Keep using what we have, but not indefinitely.
     *
     * Stale keys are a smaller problem than no keys — right up until they are a
     * year old and the provider rotated twice. Past the grace window a login
     * fails with something an operator can act on, rather than quietly relying on
     * metadata nobody has been able to confirm since.
     *
     * @param array{at:int,forced_at:int,data:array<string,mixed>} $entry
     * @return array<string, mixed>
     */
    private function stale(array $entry, string $url, int $now, ?Throwable $previous = null): array
    {
        if ($now - (int) ($entry['at'] ?? 0) > $this->ttl + $this->graceAfterExpiry) {
            throw OAuthException::of(
                'metadata_unavailable',
                'The metadata at ' . $url . ' has not been reachable since it expired.',
                $previous,
            );
        }

        return $entry['data'];
    }

    /** @return array<string, mixed> */
    private function fetch(string $url): array
    {
        $response = $this->http->sendRequest(new Request('GET', $url, ['Accept' => 'application/json']));

        if ($response->getStatusCode() !== 200) {
            throw OAuthException::of('metadata_unavailable', $url . ' answered ' . $response->getStatusCode() . '.');
        }

        $decoded = json_decode((string) $response->getBody(), true);

        if (!is_array($decoded)) {
            throw OAuthException::of('metadata_unavailable', $url . ' did not answer with a JSON object.');
        }

        return $decoded;
    }

    /** @return array{at:int,forced_at:int,failed_at:int,data:array<string,mixed>}|null */
    private function read(string $file): ?array
    {
        if (!is_file($file)) {
            return null;
        }

        $decoded = json_decode((string) @file_get_contents($file), true);

        if (!is_array($decoded) || !is_array($decoded['data'] ?? null)) {
            return null;
        }

        return [
            'at'        => (int) ($decoded['at'] ?? 0),
            'forced_at' => (int) ($decoded['forced_at'] ?? 0),
            'failed_at' => (int) ($decoded['failed_at'] ?? 0),
            'data'      => $decoded['data'],
        ];
    }

    /** @param array<string, mixed> $entry */
    private function write(string $file, array $entry): void
    {
        if (!is_dir($this->path) && !@mkdir($this->path, 0700, true) && !is_dir($this->path)) {
            return; // A cache we cannot write still works, it is only slower.
        }

        $temporary = $file . '.' . bin2hex(random_bytes(6));

        // Written aside and moved into place, so a concurrent reader never sees
        // half a document.
        if (@file_put_contents($temporary, json_encode($entry, JSON_UNESCAPED_SLASHES)) !== false) {
            @chmod($temporary, 0600);
            @rename($temporary, $file);
        }
    }
}
