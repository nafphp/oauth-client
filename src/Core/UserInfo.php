<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Core;

use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Provider\UserInfoSource;
use Nyholm\Psr7\Request;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;

/**
 * Who a provider without OpenID Connect says this is.
 *
 * The answer is reshaped into the same claims an ID token would have carried —
 * `iss`, `sub`, `email`, `email_verified`, `name` — so that everything after this
 * point treats both kinds of provider identically. The raw payload is kept
 * alongside, because a provider's own fields are often the interesting ones.
 *
 * `iss` is ours, not theirs: plain OAuth2 states no issuer, and identities still
 * need a namespace to stay apart from one another.
 */
final class UserInfo
{
    private const string AGENT = 'nixphp-oauth-client';

    public function __construct(private readonly ClientInterface $http) {}

    /** @return array<string, mixed> */
    public function claims(UserInfoSource $source, #[\SensitiveParameter] string $accessToken): array
    {
        $raw = $this->get($source->endpoint, $accessToken, $source->headers);

        $subject = $raw[$source->subjectField] ?? null;

        if (!is_string($subject) && !is_int($subject)) {
            throw OAuthException::of(
                'subject_missing',
                'The provider answered without a "' . $source->subjectField . '" to identify the account by.',
            );
        }

        $claims = $raw;
        $claims['iss'] = $source->issuer;
        $claims['sub'] = (string) $subject;

        if ($claims['sub'] === '') {
            throw OAuthException::of('subject_missing', 'The provider answered with an empty account identifier.');
        }

        if ($source->nameField !== null && is_string($raw[$source->nameField] ?? null)) {
            $claims['name'] = $raw[$source->nameField];
        }

        [$email, $verified] = $this->email($source, $raw, $accessToken);

        $claims['email']          = $email;
        $claims['email_verified'] = $verified;

        return $claims;
    }

    /**
     * @param array<string, mixed> $raw
     * @return array{0: string|null, 1: bool}
     */
    private function email(UserInfoSource $source, array $raw, #[\SensitiveParameter] string $accessToken): array
    {
        $email = $source->emailField === null ? null : $raw[$source->emailField] ?? null;

        if (is_string($email) && $email !== '') {
            $verified = $source->emailVerifiedField !== null
                && ($raw[$source->emailVerifiedField] ?? null) === true;

            return [$email, $verified];
        }

        if ($source->emailsEndpoint === null) {
            return [null, false];
        }

        // Some providers keep the address out of the profile and list it separately;
        // only the verified one there is worth anything.
        foreach ($this->addresses($source, $accessToken) as $candidate) {
            if (($candidate['verified'] ?? null) === true && is_string($candidate['email'] ?? null)) {
                if (($candidate['primary'] ?? null) === true) {
                    return [$candidate['email'], true];
                }

                $email ??= $candidate['email'];
            }
        }

        return is_string($email) && $email !== '' ? [$email, true] : [null, false];
    }

    /**
     * A missing address is not a failed login, so this never throws: plenty of
     * accounts simply have none to share.
     *
     * @return list<array<string, mixed>>
     */
    private function addresses(UserInfoSource $source, #[\SensitiveParameter] string $accessToken): array
    {
        try {
            $listed = $this->get((string) $source->emailsEndpoint, $accessToken, $source->headers);
        } catch (OAuthException) {
            return [];
        }

        return array_values(array_filter($listed, is_array(...)));
    }

    /**
     * @param array<string, string> $headers
     * @return array<mixed>
     */
    private function get(string $url, #[\SensitiveParameter] string $accessToken, array $headers): array
    {
        try {
            $response = $this->http->sendRequest(new Request('GET', $url, [
                // A User-Agent is not politeness here: some provider APIs reject a
                // request without one outright.
                'User-Agent'    => self::AGENT,
                'Accept'        => 'application/json',
                ...$headers,
                'Authorization' => 'Bearer ' . $accessToken,
            ]));
        } catch (ClientExceptionInterface $e) {
            throw OAuthException::of('userinfo_unavailable', 'Could not reach ' . $url . '.', $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw OAuthException::of('userinfo_unavailable', $url . ' answered ' . $response->getStatusCode() . '.');
        }

        $decoded = json_decode((string) $response->getBody(), true);

        if (!is_array($decoded)) {
            throw OAuthException::of('userinfo_unavailable', $url . ' did not answer with JSON.');
        }

        return $decoded;
    }
}
