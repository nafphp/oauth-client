<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Token;

use SensitiveParameter;

/**
 * What a provider handed out, and what it is actually good for.
 *
 * The scope is the granted one, not the requested one. RFC 6749 §5.1 obliges a
 * server to state `scope` in its answer whenever it issued something other than
 * what was asked for, and Google in particular lets a person untick individual
 * permissions on the consent screen. Recording the request instead would mean the
 * application believes it has access it was never given, and finds out as a 403
 * it cannot explain.
 */
final readonly class ProviderToken
{
    /** @param list<string> $scope The granted scopes, in the order the provider named them. */
    public function __construct(
        public string $provider,
        public string $issuer,
        public string $subject,
        #[SensitiveParameter] public string $accessToken,
        #[SensitiveParameter] public ?string $refreshToken = null,
        public array $scope = [],
        public ?int $expiresAt = null,
    ) {}

    /**
     * Whether this needs renewing before it is used.
     *
     * A provider that states no lifetime is not saying "forever", it is saying
     * nothing — so nothing is assumed, and the call it is used for decides. The
     * margin covers the time between this question and the request that follows.
     */
    public function hasExpired(int $skew = 60): bool
    {
        return $this->expiresAt !== null && $this->expiresAt - $skew <= time();
    }

    /** Whether every one of these was granted. */
    public function grants(string ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if (!in_array($scope, $this->scope, true)) {
                return false;
            }
        }

        return $scopes !== [];
    }

    /**
     * The same grant, renewed.
     *
     * A provider may or may not rotate the refresh token; when it sends none, the
     * one we hold stays valid and keeping it is the difference between a working
     * integration and one that asks for consent again tomorrow. The same goes for
     * the scope: an answer that omits it granted what it granted before.
     *
     * @param list<string> $scope
     */
    public function renewed(
        #[SensitiveParameter] string $accessToken,
        #[SensitiveParameter] ?string $refreshToken,
        array $scope,
        ?int $expiresAt,
    ): self {
        return new self(
            provider: $this->provider,
            issuer: $this->issuer,
            subject: $this->subject,
            accessToken: $accessToken,
            refreshToken: $refreshToken ?? $this->refreshToken,
            scope: $scope === [] ? $this->scope : $scope,
            expiresAt: $expiresAt,
        );
    }

    /**
     * Both tokens are bearer credentials: whoever reads one can act as this person
     * until it expires. A stack trace, a dumped variable and a log line are all
     * places they must not turn up in, and all three go through here.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'provider'      => $this->provider,
            'issuer'        => $this->issuer,
            'subject'       => $this->subject,
            'accessToken'   => '[redacted]',
            'refreshToken'  => $this->refreshToken === null ? null : '[redacted]',
            'scope'         => $this->scope,
            'expiresAt'     => $this->expiresAt,
        ];
    }
}
