<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Provider;

use Naf\OAuth\Client\Exception\ConfigurationException;
use Naf\OAuth\Client\Exception\OAuthException;

/**
 * One provider's settings, resolved and checked once.
 *
 * Everything that can be derived is derived here — the redirect URI from the
 * public base URL, the endpoints from the preset, the issuer and keys from the
 * provider's own discovery document — so that the application states only what
 * nobody else can know. Whatever is left unresolved raises a
 * ConfigurationException naming the exact key, because a login that fails at the
 * provider is far harder to diagnose than one that never starts.
 *
 * A provider is one of two kinds, and which one is decided here rather than
 * anywhere downstream: with OpenID Connect there is a discovery URL and a signed
 * ID token; without it there are named endpoints and a UserInfoSource.
 */
final readonly class ProviderConfig
{
    /**
     * @param string|null $discoveryUrl Set for OpenID Connect providers.
     * @param array<string, string>|null $endpoints Static stand-in for a discovery document.
     * @param list<string>|null $allowedTenants Null when the issuer is already pinned to one tenant.
     * @param array<string, string> $extraAuthorizeParams
     * @param array<string, string> $offlineParams
     * @param array<string, string> $grantParams
     */
    public function __construct(
        public string $key,
        public string $label,
        public string $clientId,
        public ?string $clientSecret,
        public string $scope,
        public string $redirectUri,
        public ?string $discoveryUrl = null,
        public ?string $issuer = null,
        public ?array $endpoints = null,
        public ?UserInfoSource $userInfo = null,
        public ?array $allowedTenants = null,
        public array $extraAuthorizeParams = [],

        // How this provider is asked for access that outlives the browser
        // session. There is no single answer: OpenID Connect Core §11 says it is
        // a scope, Google says it is a request parameter, and a provider that
        // does neither simply never issues a refresh token.
        public ?string $offlineScope = null,
        public array $offlineParams = [],

        // What it takes to be asked again once the person has already answered.
        // Without this a provider is entitled to return the permissions it
        // granted last time and ignore the new ones.
        public array $grantParams = [],

        // 'basic' is what RFC 6749 §2.3.1 says every server must accept, so it is
        // the default. Some providers document the body form instead, and sending
        // both is explicitly wrong — hence a choice rather than a guess.
        public string $clientAuth = 'basic',
    ) {}

    /**
     * Whether the provider states identity in a signed, audience-bound ID token.
     *
     * Decided by the protocol, never by whether a profile endpoint happens to be
     * configured. Those are two different things: an OpenID Connect provider may
     * well have a UserInfo endpoint worth calling, and naming it must not quietly
     * turn the login into plain OAuth2 and drop the signature check with it.
     */
    public function isOidc(): bool
    {
        return $this->discoveryUrl !== null;
    }

    /**
     * Accept this discovery document, or refuse to use it.
     *
     * The configured issuer is the trust anchor — it is the one thing about a
     * provider the application actually stated. Everything else, endpoints and
     * signing keys included, is read from a document fetched over the network, so
     * that document has to prove it belongs to the issuer before anything in it
     * is used and before any credential is sent to an address it names.
     *
     * OpenID Connect Discovery §4.3 requires exactly this comparison.
     *
     * @param array<string, mixed> $document
     */
    public function verifyDocument(array $document): void
    {
        if ($this->issuer === null) {
            return;
        }

        $stated = $document['issuer'] ?? null;

        if (!is_string($stated) || !hash_equals($this->issuer, $stated)) {
            throw OAuthException::of(
                'issuer_mismatch',
                'The metadata of ' . $this->key . ' claims to belong to '
                . (is_string($stated) ? $stated : 'nobody') . ', not to ' . $this->issuer . '.',
            );
        }
    }

    /**
     * @param array<string, mixed> $settings
     */
    public static function fromArray(string $key, array $settings, string $publicUrl, string $configPath = 'auth:logins'): self
    {
        // The key names this login; the driver says which provider is behind it.
        // Keeping them apart is what allows two Microsoft tenants, or a staging
        // Keycloak beside a production one, under names of your choosing.
        $driver = self::text($settings, 'driver') ?? $key;
        $preset = Presets::get($driver) ?? [];
        $at     = static fn(string $name): string => $configPath . ':' . $key . ':' . $name;

        $clientId = self::text($settings, 'client_id');
        if ($clientId === null) {
            throw new ConfigurationException($at('client_id') . ' is required.');
        }

        foreach ((array) ($preset['requires'] ?? []) as $required) {
            if (self::text($settings, (string) $required) === null) {
                throw new ConfigurationException(
                    $at((string) $required) . ' is required for the ' . $driver . ' driver.'
                );
            }
        }

        [$discovery, $issuer, $endpoints, $userInfo] = self::source($key, $settings, $preset, $at, $driver);

        $callback = self::text($settings, 'callback_url')
            ?? rtrim($publicUrl, '/') . '/auth/' . $key . '/callback';

        if (!str_starts_with($callback, 'https://') && !self::isLoopback($callback)) {
            throw new ConfigurationException(
                $at('callback_url') . ' must be https (or a loopback address for local development), got ' . $callback . '.'
            );
        }

        // Everything we talk to about somebody's identity, and everything we send
        // a client secret to. Plain http is only ever a local development setup,
        // and a loopback address is the only way to say so credibly.
        foreach (['discovery_url' => $discovery, 'authorize_url' => $endpoints['authorization_endpoint'] ?? null,
                  'token_url' => $endpoints['token_endpoint'] ?? null,
                  'userinfo_url' => $userInfo?->endpoint] as $name => $url) {
            if (is_string($url) && !str_starts_with($url, 'https://') && !self::isLoopback($url)) {
                throw new ConfigurationException(
                    $at((string) $name) . ' must be https (or a loopback address for local development), got ' . $url . '.'
                );
            }
        }

        return new self(
            key: $key,
            label: self::text($settings, 'label') ?? (string) ($preset['label'] ?? ucfirst($key)),
            clientId: $clientId,
            clientSecret: self::text($settings, 'client_secret'),
            scope: self::text($settings, 'scope')
                ?? (string) ($preset['scope'] ?? ($userInfo === null ? 'openid email profile' : '')),
            redirectUri: $callback,
            discoveryUrl: $discovery,
            issuer: $issuer,
            endpoints: $endpoints,
            userInfo: $userInfo,
            allowedTenants: self::allowedTenants($settings, $preset, $at),
            extraAuthorizeParams: self::stringMap($settings['authorize_params'] ?? []),

            // OpenID Connect names the scope; a preset overrules that for a
            // provider that spells it differently, and "" turns it off for one
            // that refuses the scope outright.
            offlineScope: self::text($settings, 'offline_scope')
                ?? (array_key_exists('offline_scope', $preset)
                    ? self::text($preset, 'offline_scope')
                    : ($discovery !== null ? 'offline_access' : null)),
            offlineParams: self::stringMap($preset['offline_params'] ?? []),
            grantParams: self::stringMap($preset['grant_params'] ?? []),
            clientAuth: self::text($settings, 'client_auth')
                ?? (string) ($preset['client_auth'] ?? 'basic'),
        );
    }

    /**
     * Accept the issuer this ID token claims, or explain why not.
     *
     * A discovery document may name its issuer as a template — Microsoft does this
     * for multi-tenant applications, where the real issuer only becomes known from
     * the token's own `tid`. Substituting it is safe **because** the tenant is then
     * checked against the configured list; without that list the provider would
     * never have been constructed.
     *
     * @param array<string, mixed> $claims
     */
    public function verifyIssuer(string $documentIssuer, string $tokenIssuer, array $claims): void
    {
        $expected = $documentIssuer;

        if (str_contains($documentIssuer, '{tenantid}')) {
            $tenant = $claims['tid'] ?? null;

            if (!is_string($tenant) || $tenant === '') {
                throw OAuthException::of('issuer_mismatch', 'The ID token carries no tenant, but the issuer is per-tenant.');
            }

            $expected = str_replace('{tenantid}', $tenant, $documentIssuer);

            if ($this->allowedTenants !== null
                && !in_array('*', $this->allowedTenants, true)
                && !in_array($tenant, $this->allowedTenants, true)) {
                throw OAuthException::of('tenant_not_allowed', 'Tenant ' . $tenant . ' is not in oauth:providers:' . $this->key . ':allowed_tenants.');
            }
        }

        if (!hash_equals($expected, $tokenIssuer)) {
            throw OAuthException::of('issuer_mismatch', 'Expected issuer ' . $expected . ', got ' . $tokenIssuer . '.');
        }
    }

    // ---------------------------------------------------------------- Internals

    /**
     * Decide which kind of provider this is, and resolve what that kind needs.
     *
     * Explicit application settings decide first, then the preset. A provider that
     * is neither is a configuration error rather than a guess.
     *
     * @param array<string, mixed> $settings
     * @param array<string, mixed> $preset
     * @return array{0: string|null, 1: string|null, 2: array<string, string>|null, 3: UserInfoSource|null}
     */
    private static function source(string $key, array $settings, array $preset, callable $at, string $driver): array
    {
        $userInfoUrl = self::text($settings, 'userinfo_url');
        $issuer      = self::text($settings, 'issuer');
        $discovery   = self::text($settings, 'discovery_url');

        $isOidc = $issuer !== null || $discovery !== null || isset($preset['discovery']);

        if ($isOidc) {
            $discoveryUrl = self::discoveryUrl($settings, $preset, $issuer, $discovery);

            // An OpenID Connect provider may also have a profile endpoint. Naming
            // one adds to the login; it never replaces the ID token.
            $profile = $userInfoUrl === null ? null : UserInfoSource::fromArray(
                (string) $issuer,
                self::userInfoSettings($settings, ['endpoint' => $userInfoUrl]),
            );

            return [$discoveryUrl, $issuer, null, $profile];
        }

        if ($userInfoUrl === null && !isset($preset['userinfo'])) {
            throw new ConfigurationException(
                $at('issuer') . ' is required: "' . $driver . '" is not a known driver. '
                . 'Known drivers are ' . implode(', ', Presets::names()) . '. '
                . 'For a provider without OpenID Connect, give ' . $at('authorize_url') . ', '
                . $at('token_url') . ' and ' . $at('userinfo_url') . ' instead.'
            );
        }

        /** @var array<string, mixed> $userInfoPreset */
        $userInfoPreset = (array) ($preset['userinfo'] ?? []);
        /** @var array<string, mixed> $endpointPreset */
        $endpointPreset = (array) ($preset['endpoints'] ?? []);

        $authorize = self::text($settings, 'authorize_url') ?? self::text($endpointPreset, 'authorization_endpoint');
        $token     = self::text($settings, 'token_url') ?? self::text($endpointPreset, 'token_endpoint');

        foreach (['authorize_url' => $authorize, 'token_url' => $token] as $name => $value) {
            if ($value === null) {
                throw new ConfigurationException($at($name) . ' is required for a provider without OpenID Connect.');
            }
        }

        $userInfoPreset['endpoint'] = $userInfoUrl ?? self::text($userInfoPreset, 'endpoint');

        if ($userInfoPreset['endpoint'] === null) {
            throw new ConfigurationException($at('userinfo_url') . ' is required for a provider without OpenID Connect.');
        }

        return [
            null,
            null,
            [
                // Without a discovery document, this stands in for one. The issuer is
                // ours: a plain OAuth2 provider states none, and identities still have
                // to live in some namespace to stay apart.
                'issuer'                 => 'oauth:' . $key,
                'authorization_endpoint' => (string) $authorize,
                'token_endpoint'         => (string) $token,
            ],
            UserInfoSource::fromArray('oauth:' . $key, self::userInfoSettings($settings, $userInfoPreset)),
        ];
    }

    /**
     * Field names an application may override on top of whatever the preset says.
     *
     * @param array<string, mixed> $settings
     * @param array<string, mixed> $base
     * @return array<string, mixed>
     */
    private static function userInfoSettings(array $settings, array $base): array
    {
        foreach (['subject' => 'subject_field', 'name' => 'name_field', 'email' => 'email_field'] as $field => $option) {
            if (null !== $override = self::text($settings, $option)) {
                $base[$field] = $override;
            }
        }

        return $base;
    }

    /**
     * @param array<string, mixed> $settings
     * @param array<string, mixed> $preset
     */
    private static function discoveryUrl(array $settings, array $preset, ?string $issuer, ?string $explicit): string
    {
        if ($explicit !== null) {
            return $explicit;
        }

        if (isset($preset['discovery'])) {
            $template = (string) $preset['discovery'];

            return str_contains($template, '{tenant}')
                ? str_replace('{tenant}', (string) self::text($settings, 'tenant'), $template)
                : $template;
        }

        return rtrim((string) $issuer, '/') . '/.well-known/openid-configuration';
    }

    /**
     * @param array<string, mixed> $settings
     * @param array<string, mixed> $preset
     * @return list<string>|null
     */
    private static function allowedTenants(array $settings, array $preset, callable $at): ?array
    {
        $open   = (array) ($preset['open_tenants'] ?? []);
        $tenant = self::text($settings, 'tenant');

        if ($tenant === null || !in_array($tenant, $open, true)) {
            // A single named tenant pins the issuer by itself; nothing to allow.
            return null;
        }

        $allowed = $settings['allowed_tenants'] ?? null;

        if (!is_array($allowed) || $allowed === []) {
            throw new ConfigurationException(
                $at('tenant') . ' is "' . $tenant . '", which lets more than one organisation sign in. '
                . 'List who may, in ' . $at('allowed_tenants') . ' — directory ids, or ["*"] to accept every organisation.'
            );
        }

        return array_values(array_map(strval(...), $allowed));
    }

    /** @param array<string, mixed> $settings */
    private static function text(array $settings, string $name): ?string
    {
        $value = $settings[$name] ?? null;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /** @return array<string, string> */
    private static function stringMap(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $map = [];
        foreach ($value as $name => $item) {
            if (is_string($name) && (is_string($item) || is_int($item))) {
                $map[$name] = (string) $item;
            }
        }

        return $map;
    }

    private static function isLoopback(string $url): bool
    {
        $host = parse_url($url, PHP_URL_HOST);

        return in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }
}
