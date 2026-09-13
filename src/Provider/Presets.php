<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Provider;

/**
 * What we already know about the usual providers.
 *
 * A preset exists so that a well-known provider costs nothing but its credentials.
 * It never holds anything installation-specific — no client id, no redirect URI,
 * no tenant — only facts that are the same for everybody who uses that provider.
 *
 * A preset with `discovery` speaks OpenID Connect, and its endpoints and keys are
 * read from the provider itself, so a rotated endpoint or a new signing key needs
 * no release here. A preset with `userinfo` does not: plain OAuth2 has no
 * discovery document, so those endpoints are named, and they are the only thing
 * in this file that can go stale.
 *
 * GitLab is deliberately absent: it publishes an OpenID Connect discovery
 * document, so `'issuer' => 'https://gitlab.com'` already covers it.
 */
final class Presets
{
    /** @var array<string, array<string, mixed>> */
    private const array KNOWN = [
        'google' => [
            'label'     => 'Google',
            'discovery' => 'https://accounts.google.com/.well-known/openid-configuration',
            'scope'     => 'openid email profile',

            // Google predates the standard spelling and rejects the scope, asking
            // for a request parameter instead. It also issues the refresh token
            // once, on the first consent — which is why asking again forces one.
            'offline_scope'  => null,
            'offline_params' => ['access_type' => 'offline'],
            'grant_params'   => ['prompt' => 'consent', 'include_granted_scopes' => 'true'],
        ],
        'microsoft' => [
            'label'     => 'Microsoft',
            'discovery' => 'https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration',
            'scope'     => 'openid email profile',
            'requires'  => ['tenant'],

            // Microsoft follows the standard here: a scope, and a prompt to be
            // asked again.
            'grant_params' => ['prompt' => 'consent'],

            // Tenant values that stand for more than one organisation. Choosing one
            // is a decision about who may sign in, so it demands an explicit
            // allowed_tenants list rather than opening up quietly.
            'open_tenants' => ['common', 'organizations', 'consumers'],
        ],
        'github' => [
            'label' => 'GitHub',

            // read:user for the profile, user:email because /user hides an address
            // the person has not made public.
            'scope' => 'read:user user:email',

            // GitHub documents the credentials in the request body.
            'client_auth' => 'body',

            // GitHub's tokens do not expire and it issues no refresh token, so
            // there is nothing to ask for; re-authorising is how scopes grow.
            'offline_scope' => null,
            'grant_params'  => ['prompt' => 'consent'],
            'endpoints' => [
                'authorization_endpoint' => 'https://github.com/login/oauth/authorize',
                'token_endpoint'         => 'https://github.com/login/oauth/access_token',
            ],
            'userinfo' => [
                'endpoint' => 'https://api.github.com/user',
                'subject'  => 'id',
                'name'     => 'name',
                'email'    => 'email',

                // /user answers email: null unless the address is public, so the
                // verified one is fetched from the address list instead.
                'emails_endpoint' => 'https://api.github.com/user/emails',
                'headers' => [
                    'Accept'               => 'application/vnd.github+json',
                    'X-GitHub-Api-Version' => '2022-11-28',
                ],
            ],
        ],
    ];

    /** @return array<string, mixed>|null */
    public static function get(string $key): ?array
    {
        return self::KNOWN[$key] ?? null;
    }

    /** @return list<string> */
    public static function names(): array
    {
        return array_keys(self::KNOWN);
    }
}
