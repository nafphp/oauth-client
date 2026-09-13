<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Controllers;

use NixPHP\OAuth\Client\Account\Accounts;
use NixPHP\OAuth\Client\Core\Flow;
use NixPHP\OAuth\Client\Core\OAuth;
use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Token\Tokens;
use NixPHP\Session\Core\Session;
use Psr\Http\Message\ResponseInterface;
use function NixPHP\abort;
use function NixPHP\app;
use function NixPHP\Auth\auth;
use function NixPHP\config;
use function NixPHP\log;
use function NixPHP\param;
use function NixPHP\redirect;

/**
 * The three routes that make a login work without any callback code of your own.
 *
 * There is nothing here you could not write yourself; the point is that you do
 * not have to, and that the parts which are easy to get subtly wrong — where the
 * return target comes from, which failures are a person's doing and which are
 * yours, what reaches the log — are already decided.
 */
final class OAuthController
{
    /** Send somebody off to sign in. */
    public function start(string $provider): ResponseInterface
    {
        return $this->attempt(
            $provider,
            static fn(Flow $flow): ResponseInterface => redirect($flow->authorizationUrl(self::next())),
        );
    }

    /** Send somebody already signed in off to attach this provider to their account. */
    public function connect(string $provider): ResponseInterface
    {
        auth()->requireLogin();

        return $this->attempt($provider, static fn(Flow $flow): ResponseInterface => redirect($flow->linkUrl(
            (string) auth()->providerName(),
            (string) auth()->id(),
            self::next(),
        )));
    }

    /** What the provider sends back. */
    public function callback(string $provider): ResponseInterface
    {
        return $this->attempt($provider, static function (Flow $flow): ResponseInterface {
            $callback = $flow->callback();

            app()->container()->get(Accounts::class)->complete($callback);

            // Only once it was completed. A callback nobody is allowed to finish
            // — an unlinked account, a link begun by somebody else — must not
            // leave a working credential behind on its way out.
            if (config('oauth:tokens:store', false) === true) {
                app()->container()->get(Tokens::class)->remember($callback);
            }

            return redirect($callback->redirectTo);
        });
    }

    /**
     * Run a step, and turn a refused login into a redirect rather than an error page.
     *
     * A cancelled login, an expired one, an account nobody has linked yet: these are
     * ordinary things for a person to do, not server faults, and they do not deserve
     * a stack trace. Anything else — a misconfiguration, a genuine bug — is left
     * alone to surface the way every other error in the application does.
     *
     * The reason goes into the session rather than the URL, so it cannot be dictated
     * by sending somebody a link; the message goes to the log, where it can be read.
     *
     * @param callable(Flow): ResponseInterface $step
     */
    private function attempt(string $provider, callable $step): ResponseInterface
    {
        $providers = app()->container()->get(OAuth::class);

        if (!$providers->has($provider)) {
            abort(404, 'Unknown login provider.');
        }

        try {
            return $step($providers->provider($provider));
        } catch (OAuthException $e) {
            log()->warning('OAuth login with ' . $provider . ' failed (' . $e->reason . '): ' . $e->getMessage());

            app()->container()->get(Session::class)->flash('oauth_error', $e->reason);

            return redirect((string) config('oauth:error_route', '/'));
        }
    }

    /** Where to land afterwards. Only ever a local path — Flow refuses anything else. */
    private static function next(): ?string
    {
        $next = param()->get('next');

        return is_string($next) && $next !== '' ? $next : null;
    }
}
