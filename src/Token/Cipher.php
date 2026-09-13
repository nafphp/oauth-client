<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Token;

use Naf\OAuth\Client\Exception\ConfigurationException;
use SensitiveParameter;

/**
 * Authenticated encryption for the credentials we hold on somebody's behalf.
 *
 * A stored refresh token is a standing permission to act as that person at the
 * provider until they revoke it. A copy of the database must therefore not be
 * enough to use one — which is the entire reason this class exists, and the
 * reason the key belongs somewhere other than the database it protects.
 *
 * XChaCha20-Poly1305 rather than something that merely hides the bytes: the row
 * it belongs to is fed in as associated data, so a ciphertext lifted out of one
 * row and pasted into another fails to decrypt instead of quietly working. The
 * nonce is random per write, which that construction is built to allow.
 */
final class Cipher
{
    /** A marker on every stored value, so a second format can be introduced later. */
    private const string VERSION = 'x1';

    // Named rather than taken from the SODIUM_* constants, which do not exist
    // when the extension is missing — the case this class has to report clearly.
    private const int KEY_BYTES   = 32;
    private const int NONCE_BYTES = 24;

    private function __construct(
        #[SensitiveParameter] private readonly string $key,
    ) {}

    /**
     * Build one from the configured key, or explain exactly what is wrong with it.
     *
     * @param string|null $encoded Base64 of {@see KEY_BYTES} random bytes.
     */
    public static function fromKey(#[SensitiveParameter] ?string $encoded): self
    {
        if (!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
            throw new ConfigurationException(
                'Keeping provider tokens needs ext-sodium, which this PHP build does not have. '
                . 'Install it, or turn oauth:tokens:store off and sign people in without storing anything.'
            );
        }

        if (!is_string($encoded) || trim($encoded) === '') {
            throw new ConfigurationException(
                'oauth:tokens:key is required once oauth:tokens:store is on: provider tokens are '
                . 'encrypted before they are written. Generate one with: php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"'
            );
        }

        $key = base64_decode(trim($encoded), true);

        if ($key === false || strlen($key) !== self::KEY_BYTES) {
            throw new ConfigurationException(
                'oauth:tokens:key has to be base64 of exactly ' . self::KEY_BYTES
                . ' random bytes. Generate one with: php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"'
            );
        }

        return new self($key);
    }

    public static function generateKey(): string
    {
        return base64_encode(random_bytes(self::KEY_BYTES));
    }

    /**
     * @param string $context What this value belongs to. Anything that decrypts it
     *                        has to name the same thing, or it does not decrypt.
     */
    public function encrypt(#[SensitiveParameter] string $plaintext, string $context): string
    {
        $nonce = random_bytes(self::NONCE_BYTES);

        return self::VERSION . ':' . base64_encode($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $context,
            $nonce,
            $this->key,
        ));
    }

    /**
     * @throws ConfigurationException when the value cannot be read with this key.
     */
    public function decrypt(string $stored, string $context): string
    {
        [$version, $payload] = array_pad(explode(':', $stored, 2), 2, null);

        if ($version !== self::VERSION || !is_string($payload)) {
            throw new ConfigurationException('A stored provider token is not in a format this version can read.');
        }

        $raw = base64_decode($payload, true);

        if ($raw === false || strlen($raw) <= self::NONCE_BYTES) {
            throw new ConfigurationException('A stored provider token is damaged.');
        }

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($raw, self::NONCE_BYTES),
            $context,
            substr($raw, 0, self::NONCE_BYTES),
            $this->key,
        );

        if ($plaintext === false) {
            // Either the key changed, or the row was moved. Both mean the stored
            // grant is unusable, and both are worth saying out loud rather than
            // returning an empty string that fails later at the provider.
            throw new ConfigurationException(
                'A stored provider token could not be decrypted. Either oauth:tokens:key '
                . 'changed, or the row does not belong where it is. Affected people have to '
                . 'grant access again.'
            );
        }

        return $plaintext;
    }
}
