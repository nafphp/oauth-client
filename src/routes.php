<?php

declare(strict_types=1);

use NixPHP\OAuth\Client\Controllers\OAuthController;
use function NixPHP\config;
use function NixPHP\route;

// Turn these off with oauth:routes => false when the application wants to own the
// URLs, or the flow itself. Everything here is available directly through oauth().
if (config('oauth:routes', true) !== false) {
    route()->add('GET', '/auth/{provider}', [OAuthController::class, 'start'], 'oauth.start');
    route()->add('GET', '/auth/{provider}/callback', [OAuthController::class, 'callback'], 'oauth.callback');
    route()->add('GET', '/auth/{provider}/connect', [OAuthController::class, 'connect'], 'oauth.connect');
}
