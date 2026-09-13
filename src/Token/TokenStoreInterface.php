<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Token;

/** Where a provider's own tokens are kept between requests. */
interface TokenStoreInterface
{
    public function find(string $issuer, string $subject): ?ProviderToken;

    /** Write it, replacing whatever was there for the same external identity. */
    public function put(ProviderToken $token): void;

    public function forget(string $issuer, string $subject): void;
}
