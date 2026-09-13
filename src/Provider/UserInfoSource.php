<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Provider;

/**
 * Where a provider without OpenID Connect says who somebody is.
 *
 * Plain OAuth2 has no ID token, so there is no signed assertion to check. The
 * identity comes from an authenticated call to the provider's own API with the
 * access token we have just exchanged our code for. That is a **different trust
 * path**, and worth naming plainly:
 *
 * - with OIDC, the provider signs a statement addressed to this application, and
 *   we verify that signature and that address;
 * - without it, we trust TLS to the API host plus the fact that this token was
 *   minted for our client id, against our redirect URI, with our PKCE verifier.
 *
 * For the authorization-code flow that second path is sound — no token from
 * anywhere else can reach here. It is weaker in kind, not in strength: there is
 * no audience-bound assertion to re-check later, and nothing binds the answer to
 * this particular login beyond the token itself.
 *
 * The field names exist because every provider shapes its answer differently.
 * They are the whole of what varies, which is why there is no adapter class per
 * provider and no package per provider either.
 */
final readonly class UserInfoSource
{
    /** @param array<string, string> $headers Provider quirks, e.g. an API version. */
    public function __construct(
        public string $issuer,
        public string $endpoint,
        public string $subjectField = 'sub',
        public ?string $nameField = 'name',
        public ?string $emailField = 'email',
        public ?string $emailVerifiedField = null,
        public ?string $emailsEndpoint = null,
        public array $headers = [],
    ) {}

    /**
     * @param array<string, mixed> $settings Preset entry, overlaid with application settings.
     */
    public static function fromArray(string $issuer, array $settings): self
    {
        return new self(
            issuer: $issuer,
            endpoint: (string) $settings['endpoint'],
            subjectField: (string) ($settings['subject'] ?? 'sub'),
            nameField: self::field($settings, 'name'),
            emailField: self::field($settings, 'email'),
            emailVerifiedField: self::field($settings, 'email_verified'),
            emailsEndpoint: self::field($settings, 'emails_endpoint'),
            headers: self::headers($settings['headers'] ?? []),
        );
    }

    /** @param array<string, mixed> $settings */
    private static function field(array $settings, string $name): ?string
    {
        $value = $settings[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /** @return array<string, string> */
    private static function headers(mixed $headers): array
    {
        if (!is_array($headers)) {
            return [];
        }

        $clean = [];
        foreach ($headers as $name => $value) {
            if (is_string($name) && (is_string($value) || is_int($value))) {
                $clean[$name] = (string) $value;
            }
        }

        return $clean;
    }
}
