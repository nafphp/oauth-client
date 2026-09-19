<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Core;

use Naf\OAuth\Client\Exception\OAuthException;
use Naf\OAuth\Client\Identity\ExternalIdentity;
use Naf\OAuth\Client\Provider\ProviderConfig;
use Naf\OAuth\Client\Provider\UserInfoSource;
use Naf\OAuth\Client\Token\ProviderToken;
use Nyholm\Psr7\Request;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function Naf\app;

/**
 * One provider's login, from the first redirect to the verified identity.
 *
 * Two calls: where to send the browser, and what came back. Everything the
 * protocol asks for in between — PKCE, `state`, `nonce`, the exact redirect URI,
 * the signature and claim checks — happens inside and is not configurable,
 * because none of it is a decision an application should be making.
 */
final class Flow
{
    public function __construct(
        private readonly ProviderConfig $provider,
        private readonly ClientInterface $http,
        private readonly TransactionStoreInterface $transactions,
        private readonly Metadata $metadata,
        private readonly IdToken $idToken,
        private readonly UserInfo $userInfo,
        private readonly string $afterLogin = '/',

        // Whether this installation keeps what the provider issues. It changes
        // what the authorization request asks for — offline access is not the
        // default anywhere, and asking for it when nothing will be stored only
        // puts a longer sentence on somebody's consent screen.
        private readonly bool $offlineAccess = false,
    ) {
    }

    public function key(): string
    {
        return $this->provider->key;
    }

    /** What a button for this provider says. An explicit text always wins. */
    public function label(?string $explicit = null): string
    {
        return $explicit !== null && trim($explicit) !== '' ? trim($explicit) : $this->provider->label;
    }

    /**
     * Fetch and check this provider's metadata, without starting anything.
     *
     * What a login does first, minus the part that needs a browser: no session,
     * no pending transaction, no state. For setup checks, where the question is
     * whether the provider answers and whether what it says belongs to the issuer
     * that was configured.
     *
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->document();
    }

    /** Whether identity comes from a signed ID token, or from a profile endpoint. */
    public function isOidc(): bool
    {
        return $this->provider->isOidc();
    }

    /**
     * The callback URL this provider has to be told about.
     *
     * Resolved, not rebuilt: derived from the public URL unless the application
     * stated one, and it is the exact value the token request will send. Anything
     * that prints a URL for somebody to register has to print this one, or it
     * prints something that works until the day it does not.
     */
    public function redirectUri(): string
    {
        return $this->provider->redirectUri;
    }

    /** Where to send somebody who wants to sign in. */
    public function authorizationUrl(?string $redirectTo = null): string
    {
        return $this->start(Callback::LOGIN, null, $redirectTo);
    }

    /**
     * Where to send somebody who is already signed in and wants to attach this
     * provider to their account. The person is recorded now, so the callback can
     * refuse to attach it to anybody else.
     */
    public function linkUrl(string $initiatorProvider, string $initiatorId, ?string $redirectTo = null): string
    {
        if ($initiatorProvider === '' || $initiatorId === '') {
            throw OAuthException::of('no_initiator', 'Linking a provider needs somebody signed in to link it to.');
        }

        return $this->start(Callback::LINK, ['provider' => $initiatorProvider, 'id' => $initiatorId], $redirectTo);
    }

    /**
     * Where to send somebody signed in who is about to grant more than a login needs.
     *
     * Extra permissions are asked for here, when the feature that needs them is
     * used — not at the login, where nobody can tell why a calendar is suddenly
     * being mentioned. A shorter consent screen is also a truthful one.
     *
     * It comes back through the ordinary callback and is recorded as a link,
     * because that is what it is: the same provider account, the same person,
     * more granted. Consent is forced, since a provider that considers the
     * question already answered would otherwise return the old permissions.
     *
     * @param list<string> $scopes
     */
    public function grantUrl(
        array $scopes,
        string $initiatorProvider,
        string $initiatorId,
        ?string $redirectTo = null,
    ): string {
        if ($scopes === []) {
            throw OAuthException::of('no_scopes', 'Asking for more access has to say what for.');
        }

        if ($initiatorProvider === '' || $initiatorId === '') {
            throw OAuthException::of('no_initiator', 'Granting access needs somebody signed in to grant it.');
        }

        return $this->start(
            Callback::LINK,
            ['provider' => $initiatorProvider, 'id' => $initiatorId],
            $redirectTo,
            $scopes,
            forceConsent: true,
        );
    }

    /**
     * Check what came back. Throws unless everything verifies.
     *
     * @param array<string, mixed>|null $query Null reads the current request.
     */
    public function callback(?array $query = null): Callback
    {
        $query ??= app()->container()->get(ServerRequestInterface::class)->getQueryParams();

        // The state comes first, even for a refusal. A failure report belongs to a
        // login we started as much as a success does — otherwise anybody can drive
        // this endpoint with ?error=, and a cancelled attempt stays pending until
        // it expires.
        $state = self::text($query, 'state');

        if ($state === null) {
            throw OAuthException::of('state_missing', 'The callback carries no state.');
        }

        $transaction = $this->transactions->take($state);

        if ($transaction === null) {
            throw OAuthException::of(
                'state_unknown',
                'No login is waiting for this state: it was already used, it expired, or it began in another browser.',
            );
        }

        if (($transaction['provider'] ?? null) !== $this->provider->key) {
            throw OAuthException::of('provider_mismatch', 'That login was started with a different provider.');
        }

        if (isset($query['error'])) {
            $reported = is_string($query['error']) ? $query['error'] : 'unknown';

            throw OAuthException::of('provider_error', $this->provider->key . ' refused the login: ' . $reported . '.');
        }

        $code = self::text($query, 'code');

        if ($code === null) {
            throw OAuthException::of('code_missing', 'The callback carries no authorization code.');
        }

        $document = $this->document();
        $tokens   = $this->exchange($code, (string) ($transaction['verifier'] ?? ''), $document);
        $source   = $this->provider->userInfo;

        // The protocol decides, not whether a profile endpoint happens to be
        // configured. An OpenID Connect provider stays one when it has both.
        if ($this->provider->isOidc()) {
            $idToken = $tokens['id_token'] ?? null;

            if (!is_string($idToken) || $idToken === '') {
                throw OAuthException::of('id_token_missing', $this->provider->key . ' returned no ID token.');
            }

            $claims = $this->idToken->verify($idToken, $this->provider, $document, (string) ($transaction['nonce'] ?? ''));

            // A profile endpoint adds to a verified identity; it never establishes
            // one. Reached only now, and only for the person the ID token named.
            if ($source !== null) {
                $claims = $this->withProfile($claims, $source, $tokens);
            }
        } elseif ($source !== null) {
            $accessToken = $tokens['access_token'] ?? null;

            if (!is_string($accessToken) || $accessToken === '') {
                throw OAuthException::of('access_token_missing', $this->provider->key . ' returned no access token.');
            }

            $claims = $this->userInfo->claims($source, $accessToken);
        } else {
            throw OAuthException::of('no_endpoint', $this->provider->key . ' says nothing about who signed in.');
        }

        $initiator = $transaction['initiator'] ?? null;

        return new Callback(
            identity: $this->identity($claims),
            purpose: ($transaction['purpose'] ?? null) === Callback::LINK ? Callback::LINK : Callback::LOGIN,
            initiator: is_array($initiator) && isset($initiator['provider'], $initiator['id'])
                ? ['provider' => (string) $initiator['provider'], 'id' => (string) $initiator['id']]
                : null,
            redirectTo: self::localPath($transaction['redirect'] ?? null, $this->afterLogin),

            // What was asked for is the fallback for what was granted, and the
            // request recorded it — by now it may have included scopes this
            // login did not ask for at all.
            token: $this->token($tokens, $claims, (string) ($transaction['scope'] ?? $this->provider->scope)),
        );
    }

    /**
     * Renew an access token without sending anybody anywhere.
     *
     * This is what a refresh token is for: somebody granted access once, and an
     * hour later the application still has it. When the provider refuses the
     * grant itself — revoked in their account, expired through disuse,
     * invalidated by a password change — that is a decision rather than a fault,
     * so it is reported as `consent_required` and what we hold is worthless.
     * Every other refusal may well be temporary and says so.
     */
    public function refresh(ProviderToken $token): ProviderToken
    {
        if ($token->refreshToken === null) {
            throw OAuthException::of(
                'consent_required',
                $this->provider->key . ' issued no refresh token, so there is nothing to renew with.',
            );
        }

        [$status, $answer] = $this->post(
            $this->endpoint($this->document(), 'token_endpoint'),
            ['grant_type' => 'refresh_token', 'refresh_token' => $token->refreshToken],
            'token endpoint',
        );

        if ($status !== 200 || isset($answer['error'])) {
            $error = is_string($answer['error'] ?? null) ? $answer['error'] : 'http_' . $status;

            throw OAuthException::of(
                // RFC 6749 §5.2 reserves invalid_grant for a refresh token that is
                // no longer one. It is the only refusal that means asking again
                // will not help, and the only one worth interrupting somebody for.
                $error === 'invalid_grant' ? 'consent_required' : 'refresh_failed',
                $this->provider->key . ' refused to renew the token: ' . $error . '.',
            );
        }

        $accessToken = self::text($answer, 'access_token');

        if ($accessToken === null) {
            throw OAuthException::of('refresh_failed', $this->provider->key . ' renewed the grant but issued no token.');
        }

        return $token->renewed(
            accessToken: $accessToken,
            refreshToken: self::text($answer, 'refresh_token'),
            scope: self::scopesOf($answer['scope'] ?? null),
            expiresAt: self::expiryOf($answer),
        );
    }

    /**
     * Tell the provider we are finished with a grant.
     *
     * Deleting our copy only makes the application forget. The permission stays
     * listed in the person's account at the provider, looking current, until
     * somebody says otherwise — and saying so is our side of the bargain, not
     * theirs. Best effort by design: a provider that publishes no revocation
     * endpoint cannot be told, RFC 7009 §2.2 has the ones that can answer success
     * for a token they have never heard of, and neither is a failure worth
     * putting in front of somebody who is signing out.
     */
    public function revoke(ProviderToken $token): void
    {
        $endpoint = $this->document()['revocation_endpoint'] ?? null;

        if (!is_string($endpoint) || $endpoint === '') {
            return;
        }

        // The refresh token first: revoking it takes the standing permission with
        // it, which is the part that outlives everything else.
        foreach ([['refresh_token', $token->refreshToken], ['access_token', $token->accessToken]] as [$hint, $value]) {
            if (!is_string($value) || $value === '') {
                continue;
            }

            try {
                $this->send($endpoint, ['token' => $value, 'token_type_hint' => $hint], 'revocation endpoint');
            } catch (OAuthException) {
                // Unreachable, refused, or already gone. The row is going either way.
            }
        }
    }

    // ---------------------------------------------------------------- Internals

    /**
     * @param array{provider:string,id:string}|null $initiator
     * @param list<string> $extraScopes
     */
    private function start(
        string $purpose,
        ?array $initiator,
        ?string $redirectTo,
        array $extraScopes = [],
        bool $forceConsent = false,
    ): string {
        $document = $this->document();
        $endpoint = $this->endpoint($document, 'authorization_endpoint');
        $scope    = $this->scope($extraScopes);

        $state    = self::random();
        $nonce    = self::random();
        $verifier = self::random();

        $this->transactions->put($state, [
            'provider'  => $this->provider->key,
            'purpose'   => $purpose,
            'nonce'     => $nonce,
            'verifier'  => $verifier,
            'initiator' => $initiator,
            'redirect'  => self::localPath($redirectTo, $this->afterLogin),
            'scope'     => $scope,
        ]);

        $parameters = [
            'response_type'         => 'code',
            'client_id'             => $this->provider->clientId,
            'redirect_uri'          => $this->provider->redirectUri,
            'scope'                 => $scope,
            'state'                 => $state,
            'code_challenge'        => self::base64url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ]
            // A nonce binds an ID token to this login. Without OpenID Connect there
            // is no ID token to bind, so sending one would be decoration.
            + ($this->provider->isOidc() ? ['nonce' => $nonce] : [])

            // An application that states a parameter itself outranks anything we
            // would have added on its behalf, and is outranked in turn by the
            // protocol's own — which are not opinions.
            + $this->provider->extraAuthorizeParams
            + ($this->offlineAccess ? $this->provider->offlineParams : [])
            + ($forceConsent ? $this->provider->grantParams : []);

        return $endpoint
            . (str_contains($endpoint, '?') ? '&' : '?')
            . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param array<string, mixed> $document
     * @return array<string, mixed>
     */
    private function exchange(string $code, string $verifier, array $document): array
    {
        // An authorization code is spent the moment it reaches the provider,
        // whether or not the answer reaches us. It is single use either way, so
        // there is nothing to retry and nothing to salvage.
        [$status, $tokens] = $this->post($this->endpoint($document, 'token_endpoint'), [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->provider->redirectUri,
            'client_id'     => $this->provider->clientId,
            'code_verifier' => $verifier,
        ], 'token endpoint');

        if ($status !== 200 || isset($tokens['error'])) {
            $error = is_string($tokens['error'] ?? null) ? $tokens['error'] : 'http_' . $status;

            throw OAuthException::of('token_request_failed', 'The token endpoint refused the code: ' . $error . '.');
        }

        return $tokens;
    }

    /**
     * The endpoint of that name, or a refusal that says which document lacks it.
     *
     * @param array<string, mixed> $document
     */
    private function endpoint(array $document, string $name): string
    {
        $endpoint = $document[$name] ?? null;

        if (!is_string($endpoint) || $endpoint === '') {
            throw OAuthException::of(
                'no_endpoint',
                'The discovery document of ' . $this->provider->key . ' names no ' . $name . '.',
            );
        }

        return $endpoint;
    }

    /**
     * One form-encoded POST to the provider, with this client's credentials on it.
     *
     * @param array<string, string> $body
     * @return array{0: int, 1: array<string, mixed>} The status, and the decoded answer.
     */
    private function post(string $endpoint, array $body, string $what): array
    {
        $response = $this->send($endpoint, $body, $what);
        $answer   = json_decode((string) $response->getBody(), true);

        if (!is_array($answer)) {
            throw OAuthException::of('token_request_failed', 'The ' . $what . ' answered with something other than JSON.');
        }

        return [$response->getStatusCode(), $answer];
    }

    /**
     * @param array<string, string> $body
     */
    private function send(string $endpoint, array $body, string $what): ResponseInterface
    {
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept'       => 'application/json',
        ];

        $body['client_id'] ??= $this->provider->clientId;

        if ($this->provider->clientSecret !== null) {
            if ($this->provider->clientAuth === 'body') {
                $body['client_secret'] = $this->provider->clientSecret;
            } else {
                // client_secret_basic keeps the secret out of the body, and out of any
                // log line that records one. RFC 6749 §2.3.1 form-encodes both halves.
                $headers['Authorization'] = 'Basic ' . base64_encode(
                    rawurlencode($this->provider->clientId) . ':' . rawurlencode($this->provider->clientSecret),
                );
            }
        }

        try {
            return $this->http->sendRequest(new Request(
                'POST',
                $endpoint,
                $headers,
                http_build_query($body, '', '&', PHP_QUERY_RFC3986),
            ));
        } catch (ClientExceptionInterface $e) {
            throw OAuthException::of('token_request_failed', 'The ' . $what . ' could not be reached.', $e);
        }
    }

    /**
     * What the provider issued, as something that can be stored and reasoned about.
     *
     * @param array<string, mixed> $tokens
     * @param array<string, mixed> $claims
     */
    private function token(array $tokens, array $claims, string $requested): ?ProviderToken
    {
        $accessToken = self::text($tokens, 'access_token');

        if ($accessToken === null) {
            return null;
        }

        return new ProviderToken(
            provider: $this->provider->key,
            issuer: (string) $claims['iss'],
            subject: (string) $claims['sub'],
            accessToken: $accessToken,
            refreshToken: self::text($tokens, 'refresh_token'),

            // RFC 6749 §5.1: an answer states its scope only when it differs from
            // the request, so silence means "what you asked for" — and anything
            // else means somebody unticked a box.
            scope: self::scopesOf($tokens['scope'] ?? $requested),
            expiresAt: self::expiryOf($tokens),
        );
    }

    /**
     * Everything this authorization request should ask for.
     *
     * @param list<string> $extra
     */
    private function scope(array $extra): string
    {
        $scopes = self::scopesOf($this->provider->scope);

        if ($this->offlineAccess && $this->provider->offlineScope !== null) {
            $extra[] = $this->provider->offlineScope;
        }

        foreach ($extra as $one) {
            if ($one !== '' && !in_array($one, $scopes, true)) {
                $scopes[] = $one;
            }
        }

        return implode(' ', $scopes);
    }

    /**
     * Scopes are space-delimited in RFC 6749 §3.3 and comma-delimited at GitHub,
     * so both are read and only the space-delimited form is ever written.
     *
     * @return list<string>
     */
    private static function scopesOf(mixed $granted): array
    {
        if (!is_string($granted) || trim($granted) === '') {
            return [];
        }

        return array_values(array_filter(
            (array) preg_split('/[\s,]+/', trim($granted)),
            static fn(mixed $scope): bool => is_string($scope) && $scope !== '',
        ));
    }

    /**
     * When the access token stops working, as a point in time rather than a duration.
     *
     * A duration is only meaningful next to the moment it was issued, and that
     * moment is now; storing it as one would make every read have to remember
     * when the row was written.
     *
     * @param array<string, mixed> $tokens
     */
    private static function expiryOf(array $tokens): ?int
    {
        $lifetime = $tokens['expires_in'] ?? null;

        if (is_string($lifetime) && ctype_digit($lifetime)) {
            $lifetime = (int) $lifetime;
        }

        return is_int($lifetime) && $lifetime > 0 ? time() + $lifetime : null;
    }

    /**
     * Fold a provider's own profile answer into an already verified identity.
     *
     * The ID token decides who this is; the profile only fills in what it did not
     * say. A profile describing somebody else is not extra detail, it is a
     * different person — so the subjects have to match, and nothing from the
     * profile may overwrite a claim that was signed.
     *
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $tokens
     * @return array<string, mixed>
     */
    private function withProfile(array $claims, UserInfoSource $source, array $tokens): array
    {
        $accessToken = $tokens['access_token'] ?? null;

        if (!is_string($accessToken) || $accessToken === '') {
            return $claims;
        }

        $profile = $this->userInfo->claims($source, $accessToken);
        $subject = $profile['sub'] ?? null;

        if (!is_string($subject) || !hash_equals((string) $claims['sub'], $subject)) {
            throw OAuthException::of('subject_mismatch', 'The profile endpoint answered about somebody else.');
        }

        // Left wins: what was signed stays.
        return $claims + $profile;
    }

    /**
     * What stands in for a discovery document.
     *
     * With OpenID Connect it is the provider's own, fetched and cached. Without,
     * it is the endpoints named in the preset or the configuration — the same
     * keys, so nothing downstream has to know which kind it is holding.
     *
     * @return array<string, mixed>
     */
    private function document(): array
    {
        if ($this->provider->discoveryUrl === null) {
            return (array) $this->provider->endpoints;
        }

        $document = $this->metadata->document($this->provider->discoveryUrl);

        // Checked before a single endpoint out of it is used, and well before a
        // client secret is sent to an address it names.
        $this->provider->verifyDocument($document);

        return $document;
    }

    /** @param array<string, mixed> $claims */
    private function identity(array $claims): ExternalIdentity
    {
        $email = $claims['email'] ?? null;
        $name  = $claims['name'] ?? null;

        return new ExternalIdentity(
            provider: $this->provider->key,
            issuer: (string) $claims['iss'],
            subject: (string) $claims['sub'],
            claims: $claims,
            email: is_string($email) && $email !== '' ? $email : null,

            // Anything but a literal true is "we do not know", and an address we do
            // not know is not proof of anything.
            emailVerified: ($claims['email_verified'] ?? null) === true,
            name: is_string($name) && $name !== '' ? $name : null,
        );
    }

    /** @param array<string, mixed> $query */
    private static function text(array $query, string $name): ?string
    {
        $value = $query[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * An open redirect is one forgotten check away, so anything that is not an
     * unmistakably local path falls back to the configured landing page. A leading
     * "//" or "/\" is a URL to somewhere else in every browser that matters.
     */
    private static function localPath(mixed $target, string $fallback): string
    {
        if (!is_string($target) || $target === '' || !str_starts_with($target, '/')
            || str_starts_with($target, '//') || str_starts_with($target, '/\\')) {
            return $fallback;
        }

        // Browsers strip tabs and newlines while normalising a URL, so
        // "/\r//evil.test" reaches the address bar as "//evil.test" — the
        // protocol-relative form again, past a check that only looked at the
        // shape. Reject the characters rather than the shapes they hide.
        if (preg_match('/[\x00-\x20\x7F]/', $target) === 1) {
            return $fallback;
        }

        return $target;
    }

    private static function random(): string
    {
        return self::base64url(random_bytes(32));
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
