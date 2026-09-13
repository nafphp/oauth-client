<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;

/** An RSA key pair that behaves like a provider's: it publishes a JWKS and mints ID tokens. */
final class Signer
{
    private OpenSSLAsymmetricKey $key;

    public function __construct(private readonly string $kid = 'key-1')
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($key === false) {
            throw new \RuntimeException('Could not generate a test key.');
        }

        $this->key = $key;
    }

    public function kid(): string
    {
        return $this->kid;
    }

    /** @return array{keys: list<array<string, string>>} */
    public function jwks(): array
    {
        $details = openssl_pkey_get_details($this->key);

        return ['keys' => [[
            'kty' => 'RSA',
            'kid' => $this->kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => self::base64url((string) $details['rsa']['n']),
            'e'   => self::base64url((string) $details['rsa']['e']),
        ]]];
    }

    /** @param array<string, mixed> $claims */
    public function sign(array $claims): string
    {
        openssl_pkey_export($this->key, $pem);

        return JWT::encode($claims, $pem, 'RS256', $this->kid);
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
