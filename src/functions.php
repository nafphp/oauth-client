<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client;

use NixPHP\OAuth\Client\Core\Flow;
use NixPHP\OAuth\Client\Core\OAuth;
use NixPHP\OAuth\Client\Token\ProviderToken;
use NixPHP\OAuth\Client\Token\Tokens;
use function NixPHP\app;

/** The configured external provider of that name, registered by the plugin bootstrap. */
function oauth(string $provider): Flow
{
    return app()->container()->get(OAuth::class)->provider($provider);
}

/**
 * A provider token for the signed-in account that can be used right now.
 *
 * Renewed on the way out if it had expired. Null means nobody has granted this
 * application that access, or they have taken it back — in both cases the answer
 * is to ask, with Flow::grantUrl().
 */
function oauth_token(string $provider): ?ProviderToken
{
    return app()->container()->get(Tokens::class)->of($provider);
}
