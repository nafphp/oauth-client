<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Core;

use Naf\OAuth\Client\Identity\ExternalIdentity;
use Naf\OAuth\Client\Token\ProviderToken;

/**
 * A callback that verified, and what the login it belongs to was for.
 *
 * `purpose` matters as much as the identity. Signing in and attaching a second
 * provider to an account look identical at the callback, so the two are told
 * apart by what was recorded when the login started — never by what comes back
 * in the URL. A link started by one person cannot be finished by another,
 * because `initiator` says who began it.
 */
final readonly class Callback
{
    public const string LOGIN = 'login';
    public const string LINK  = 'link';

    /**
     * @param array{provider:string,id:string}|null $initiator
     * @param ProviderToken|null $token What the provider issued along with the identity.
     *                                  Present whenever there was an access token at
     *                                  all; kept only where an installation asked for
     *                                  that. A login needs none of it.
     */
    public function __construct(
        public ExternalIdentity $identity,
        public string $purpose,
        public ?array $initiator,
        public string $redirectTo,
        public ?ProviderToken $token = null,
    ) {}

    public function isLogin(): bool
    {
        return $this->purpose === self::LOGIN;
    }

    public function isLink(): bool
    {
        return $this->purpose === self::LINK;
    }
}
