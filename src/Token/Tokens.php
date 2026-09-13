<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Token;

use Naf\Auth\Auth;
use Naf\Auth\Identity\IdentityInterface;
use Naf\OAuth\Client\Account\Accounts;
use Naf\OAuth\Client\Core\Callback;
use Naf\OAuth\Client\Core\OAuth;
use Naf\OAuth\Client\Exception\OAuthException;

/**
 * The provider tokens an account holds, kept usable.
 *
 * A login needs none of this. It exists for the other thing an external provider
 * is good for — reading somebody's calendar, posting on their behalf — where the
 * application has to act between visits, long after the browser that carried the
 * consent has gone.
 *
 * The one promise made here is that a token handed out is one the provider will
 * still accept: an expired one is renewed on the way out, and the renewal is
 * written back, because a refresh token a provider has rotated is worth exactly
 * one use and losing that use costs somebody a consent screen.
 */
final class Tokens
{
    public function __construct(
        private readonly TokenStoreInterface $store,
        private readonly OAuth $providers,
        private readonly Accounts $accounts,
        private readonly Auth $auth,
    ) {}

    /**
     * Keep what a finished callback brought back.
     *
     * Called after the callback has been completed, never before: a login that
     * nobody may finish — an unlinked account, a link started by somebody else —
     * must not leave a working credential behind.
     */
    public function remember(Callback $callback): void
    {
        if ($callback->token !== null) {
            $this->store->put($callback->token);
        }
    }

    /**
     * A token for this provider that can be used right now, or null.
     *
     * Null means the same thing every time it is returned: nobody has granted
     * this application that access, or they have taken it back. Both are answered
     * by asking again — see Flow::grantUrl(). A provider that cannot be reached,
     * on the other hand, is an outage and says so, because letting that look like
     * a withdrawn consent would send people through a consent screen that cannot
     * fix anything.
     */
    public function of(string $provider, ?IdentityInterface $user = null, ?string $userProvider = null): ?ProviderToken
    {
        if ($user === null) {
            $user          = $this->auth->user();
            $userProvider ??= $this->auth->providerName();
        }

        if ($user === null) {
            return null;
        }

        foreach ($this->accounts->of($user, $userProvider) as $link) {
            if ($link->provider === $provider) {
                return $this->usable($this->store->find($link->issuer, $link->subject));
            }
        }

        return null;
    }

    /**
     * Give a grant back, and forget it.
     *
     * Belongs wherever a link is removed. An application that unlinks a provider
     * without this leaves the permission standing in somebody's account at the
     * provider, where it looks current and nothing will ever use it again.
     */
    public function forget(string $provider, ?IdentityInterface $user = null, ?string $userProvider = null): void
    {
        if ($user === null) {
            $user          = $this->auth->user();
            $userProvider ??= $this->auth->providerName();
        }

        if ($user === null) {
            return;
        }

        foreach ($this->accounts->of($user, $userProvider) as $link) {
            if ($link->provider === $provider) {
                $this->drop($this->store->find($link->issuer, $link->subject));
            }
        }
    }

    // ---------------------------------------------------------------- Internals

    private function usable(?ProviderToken $token): ?ProviderToken
    {
        if ($token === null || !$token->hasExpired()) {
            return $token;
        }

        try {
            $renewed = $this->providers->provider($token->provider)->refresh($token);
        } catch (OAuthException $e) {
            if ($e->reason !== 'consent_required') {
                throw $e;
            }

            // The provider no longer honours the grant. What we hold is a stale
            // copy of a permission that has been withdrawn, and keeping it would
            // only mean failing this way again on every request.
            $this->store->forget($token->issuer, $token->subject);

            return null;
        }

        $this->store->put($renewed);

        return $renewed;
    }

    private function drop(?ProviderToken $token): void
    {
        if ($token === null) {
            return;
        }

        // Told first, deleted second. The other order loses the only copy of the
        // credential that revocation needs.
        $this->providers->provider($token->provider)->revoke($token);
        $this->store->forget($token->issuer, $token->subject);
    }
}
