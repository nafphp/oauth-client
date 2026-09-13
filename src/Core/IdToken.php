<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Core;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Provider\ProviderConfig;
use Throwable;

/**
 * Verifying an ID token: the signature first, then every claim that binds it.
 *
 * The signature is always checked. There is a reading of OIDC Core §3.1.3.7 under
 * which a token fetched straight from the token endpoint over TLS may skip it,
 * and that reading is correct — but it holds only as long as nothing else can
 * ever hand us a token, which is a property of the whole application rather than
 * of this class. Checking it costs one cached document, so it is not traded away.
 * A provider whose keys cannot be read makes the login fail; it never makes the
 * check optional.
 *
 * A signature alone says the provider issued *a* token. The claim checks are what
 * say it was issued for this application, for this login, and now.
 */
final class IdToken
{
    private const int LEEWAY = 60;

    public function __construct(private readonly Metadata $metadata) {}

    /**
     * @param array<string, mixed> $document The provider's discovery document.
     * @return array<string, mixed> The verified claims.
     */
    public function verify(string $jwt, ProviderConfig $provider, array $document, string $nonce): array
    {
        // Checked here as well as where the document is fetched. This method is
        // handed a document rather than fetching one, and a verifier that trusts
        // what it was given verifies nothing: the configured issuer is the anchor,
        // wherever the document came from.
        $provider->verifyDocument($document);

        $jwksUri = $document['jwks_uri'] ?? null;

        if (!is_string($jwksUri) || $jwksUri === '') {
            throw OAuthException::of('no_jwks', 'The discovery document of ' . $provider->key . ' names no jwks_uri.');
        }

        $permitted = $this->permittedAlgorithms($document);
        $claims    = $this->decode($jwt, $jwksUri, $permitted);

        $issuer = $document['issuer'] ?? null;
        if (!is_string($issuer) || $issuer === '') {
            throw OAuthException::of('no_issuer', 'The discovery document of ' . $provider->key . ' names no issuer.');
        }

        $tokenIssuer = $claims['iss'] ?? null;
        if (!is_string($tokenIssuer)) {
            throw OAuthException::of('issuer_mismatch', 'The ID token carries no issuer.');
        }

        $provider->verifyIssuer($issuer, $tokenIssuer, $claims);

        $this->verifyAudience($claims, $provider->clientId);

        $presented = $claims['nonce'] ?? null;
        if (!is_string($presented) || !hash_equals($nonce, $presented)) {
            throw OAuthException::of('nonce_mismatch', 'The ID token belongs to a different login.');
        }

        if (!is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw OAuthException::of('subject_missing', 'The ID token names no subject.');
        }

        // exp and iat are required by OpenID Connect Core §2. The JWT library only
        // checks them when they are there, so a token that simply omits them
        // verifies and then never expires.
        foreach (['exp', 'iat'] as $claim) {
            if (!is_int($claims[$claim] ?? null)) {
                throw OAuthException::of('id_token_invalid', 'The ID token carries no usable ' . $claim . '.');
            }
        }

        return $claims;
    }

    /**
     * @param list<string> $permitted
     * @return array<string, mixed>
     */
    private function decode(string $jwt, string $jwksUri, array $permitted): array
    {
        $header = self::header($jwt);
        $algorithm = $header['alg'] ?? null;

        // Which algorithms are acceptable is the provider's published policy, not
        // a field of the token being checked. A token that names anything else —
        // "none" above all — is refused before a key is even looked up.
        if (!is_string($algorithm) || !in_array($algorithm, $permitted, true)) {
            throw OAuthException::of(
                'id_token_invalid',
                'The ID token is signed with an algorithm this provider does not publish.',
            );
        }

        $keys     = $this->keys($jwksUri, is_string($header['kid'] ?? null) ? $header['kid'] : null, $algorithm);
        $previous = JWT::$leeway;

        // Clocks drift, and a token minted a moment ago must not look like one from
        // the future. The window is small enough to be worthless to an attacker.
        JWT::$leeway = self::LEEWAY;

        try {
            $payload = JWT::decode($jwt, $keys);
        } catch (Throwable $e) {
            throw OAuthException::of('id_token_invalid', 'The ID token did not verify: ' . $e->getMessage(), $e);
        } finally {
            JWT::$leeway = $previous;
        }

        $claims = json_decode((string) json_encode($payload), true);

        return is_array($claims) ? $claims : [];
    }

    /**
     * The provider's current keys, reloaded once when this token names one we do
     * not have — which is what a key rotation looks like from this side.
     *
     * @return array<string, \Firebase\JWT\Key>
     */
    private function keys(string $jwksUri, ?string $keyId, string $defaultAlgorithm): array
    {
        $keys = $this->parse($this->metadata->jwks($jwksUri), $defaultAlgorithm);

        if ($keyId !== null && !isset($keys[$keyId])) {
            $keys = $this->parse($this->metadata->jwks($jwksUri, refresh: true), $defaultAlgorithm);
        }

        if ($keys === []) {
            throw OAuthException::of('no_keys', 'The provider published no usable signing keys.');
        }

        return $keys;
    }

    /**
     * @param array<string, mixed> $jwks
     * @return array<string, \Firebase\JWT\Key>
     */
    private function parse(array $jwks, string $defaultAlgorithm): array
    {
        try {
            return JWK::parseKeySet($jwks, $defaultAlgorithm);
        } catch (Throwable $e) {
            throw OAuthException::of('no_keys', 'The provider\'s key set could not be read: ' . $e->getMessage(), $e);
        }
    }

    /**
     * Several audiences mean the token was minted for more than one party, and
     * then the authorised party has to say it is us. OIDC Core §3.1.3.7, 3 to 5.
     *
     * @param array<string, mixed> $claims
     */
    private function verifyAudience(array $claims, string $clientId): void
    {
        $audience = $claims['aud'] ?? null;
        $audiences = is_string($audience) ? [$audience] : (is_array($audience) ? $audience : []);

        if (!in_array($clientId, $audiences, true)) {
            throw OAuthException::of('audience_mismatch', 'The ID token was not issued for this application.');
        }

        // Whenever azp is present it has to be us — not only when there are several
        // audiences. A token naming somebody else as the authorised party was
        // minted for that somebody else, however short its audience list is.
        if (array_key_exists('azp', $claims) && $claims['azp'] !== $clientId) {
            throw OAuthException::of('audience_mismatch', 'The ID token names another authorised party.');
        }
    }

    /**
     * The header, read without trusting it.
     *
     * Nothing in here is evidence. `kid` only decides which key to try, and `alg`
     * only has to survive being compared against what the provider publishes.
     *
     * @return array<string, mixed>
     */
    private static function header(string $jwt): array
    {
        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw OAuthException::of('id_token_invalid', 'The ID token is not a JWT.');
        }

        $header = json_decode((string) base64_decode(strtr($segments[0], '-_', '+/'), true), true);

        return is_array($header) ? $header : [];
    }

    /**
     * Some key sets leave `alg` off their keys. The discovery document says which
     * algorithms the provider signs with, so that is what fills the gap — never a
     * value we picked ourselves.
     *
     * @param array<string, mixed> $document
     * @return list<string>
     */
    private function permittedAlgorithms(array $document): array
    {
        $supported = $document['id_token_signing_alg_values_supported'] ?? null;
        $names = is_array($supported) ? array_values(array_filter($supported, is_string(...))) : [];

        // A provider that publishes nothing gets the one algorithm every OpenID
        // Connect provider must support. Guessing wider would mean accepting
        // whatever a token asked to be checked with.
        $names = $names === [] ? ['RS256'] : $names;

        return array_values(array_filter($names, static fn(string $a): bool => strtolower($a) !== 'none'));
    }
}
