<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/** A provider that answers from a script, and remembers what it was asked. */
final class FakeHttp implements ClientInterface
{
    /** @var array<string, array{0:int,1:string}> */
    private array $script = [];

    /** @var list<RequestInterface> */
    public array $sent = [];

    /** @var array<string, int> */
    private array $counts = [];

    /** Scripts what this URL answers from now on. Calling it again replaces that answer. */
    public function on(string $method, string $url, mixed $body, int $status = 200): void
    {
        $this->script[self::key($method, $url)] = [$status, is_string($body) ? $body : (string) json_encode($body)];
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $key = self::key($request->getMethod(), (string) $request->getUri());

        $this->sent[]       = $request;
        $this->counts[$key] = ($this->counts[$key] ?? 0) + 1;

        if (!isset($this->script[$key])) {
            throw new RuntimeException('Nothing scripted for ' . $key);
        }

        [$status, $body] = $this->script[$key];

        return new Response($status, ['Content-Type' => 'application/json'], $body);
    }

    public function calls(string $method, string $url): int
    {
        return $this->counts[self::key($method, $url)] ?? 0;
    }

    /** The most recent request to that endpoint — not simply the most recent request. */
    public function lastRequest(string $method, string $url): ?RequestInterface
    {
        $key = self::key($method, $url);

        foreach (array_reverse($this->sent) as $request) {
            if (self::key($request->getMethod(), (string) $request->getUri()) === $key) {
                return $request;
            }
        }

        return null;
    }

    public function lastBody(string $method, string $url): string
    {
        $request = $this->lastRequest($method, $url);

        if ($request === null) {
            return '';
        }

        $request->getBody()->rewind();

        return (string) $request->getBody();
    }

    private static function key(string $method, string $url): string
    {
        return strtoupper($method) . ' ' . $url;
    }
}
