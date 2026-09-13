<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client;

use NixPHP\OAuth\Client\Core\OAuth;
use function NixPHP\app;
use function NixPHP\route;

/**
 * A link that starts a login with this provider.
 *
 * The wording is settled here, highest first: what you pass in, then the view you
 * overrode, then oauth:providers:<key>:label, then the provider's own name. None
 * of it touches an issuer, a client id or a redirect URI — a label is a label.
 *
 * Override the markup by putting your own `oauth/button.phtml` in the
 * application's view directory; it wins over the one shipped here.
 */
function oauth_button(string $provider, ?string $label = null, ?string $next = null): string
{
    $text = app()->container()->get(OAuth::class)->provider($provider)->label($label);
    $url  = route('oauth.start', ['provider' => $provider]);

    if ($next !== null && $next !== '') {
        $url .= '?next=' . rawurlencode($next);
    }

    return render_oauth_view('oauth.button', [
        'provider' => $provider,
        'label'    => $text,
        'url'      => $url,
    ]);
}

/**
 * Render one of this plugin's views.
 *
 * With nixphp/view installed this goes through its template resolution, which is
 * what lets an application shadow the file. Without it, the shipped template is
 * rendered directly — same markup, no override.
 *
 * @param array<string, mixed> $variables
 * @internal
 */
function render_oauth_view(string $template, array $variables): string
{
    if (function_exists('NixPHP\View\view')) {
        return \NixPHP\View\view($template, $variables);
    }

    extract($variables);
    ob_start();
    include __DIR__ . '/views/' . str_replace('.', '/', $template) . '.phtml';

    return (string) ob_get_clean();
}
