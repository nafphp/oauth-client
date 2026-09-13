<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Exception;

use RuntimeException;
use Throwable;

/**
 * A login that did not verify.
 *
 * Every instance carries a short, stable `reason` alongside its message, so tests
 * and error pages can tell a replayed callback from an expired one without
 * matching on prose. The message is for the log; the reason is for the code.
 */
final class OAuthException extends RuntimeException
{
    private function __construct(public readonly string $reason, string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    public static function of(string $reason, string $message, ?Throwable $previous = null): self
    {
        return new self($reason, $message, $previous);
    }
}
