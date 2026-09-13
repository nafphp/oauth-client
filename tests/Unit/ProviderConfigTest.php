<?php

declare(strict_types=1);

namespace Tests\Unit;

use NixPHP\OAuth\Client\Exception\ConfigurationException;
use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Provider\ProviderConfig;
use PHPUnit\Framework\TestCase;

/** What an application has to state, and what it gets for free. */
final class ProviderConfigTest extends TestCase
{
    private const string APP = 'https://app.example.test';

    public function testAKnownProviderNeedsNothingButItsCredentials(): void
    {
        $provider = ProviderConfig::fromArray('google', [
            'client_id'     => 'abc',
            'client_secret' => 'shhh',
        ], self::APP);

        self::assertSame('Google', $provider->label);
        self::assertSame('openid email profile', $provider->scope);
        self::assertSame('https://accounts.google.com/.well-known/openid-configuration', $provider->discoveryUrl);
        self::assertSame(self::APP . '/auth/google/callback', $provider->redirectUri);
        self::assertNull($provider->allowedTenants);
    }

    // ------------------------------------------------- Name and driver

    public function testTheSameProviderCanBeConfiguredTwiceUnderNamesOfYourChoosing(): void
    {
        $staff = ProviderConfig::fromArray('staff', [
            'driver' => 'microsoft', 'client_id' => 'a', 'tenant' => 'tenant-a',
        ], self::APP);

        $partners = ProviderConfig::fromArray('partners', [
            'driver' => 'microsoft', 'client_id' => 'b', 'tenant' => 'tenant-b',
        ], self::APP);

        self::assertSame('Microsoft', $staff->label);
        self::assertSame('Microsoft', $partners->label);

        // Separate logins, so separate callbacks and separate credentials.
        self::assertSame(self::APP . '/auth/staff/callback', $staff->redirectUri);
        self::assertSame(self::APP . '/auth/partners/callback', $partners->redirectUri);
        self::assertStringContainsString('tenant-a', $staff->discoveryUrl);
        self::assertStringContainsString('tenant-b', $partners->discoveryUrl);
    }

    public function testWithoutADriverTheNameIsTheDriver(): void
    {
        $provider = ProviderConfig::fromArray('google', ['client_id' => 'abc'], self::APP);

        self::assertSame('Google', $provider->label);
    }

    public function testAnUnknownDriverIsNamedAsTheDriver(): void
    {
        $this->assertConfigurationError(
            '"nope" is not a known driver',
            fn() => ProviderConfig::fromArray('staff', ['driver' => 'nope', 'client_id' => 'a'], self::APP),
        );
    }

    public function testTwoPlainProvidersOfOneDriverKeepSeparateIdentities(): void
    {
        $first = ProviderConfig::fromArray('work', [
            'driver' => 'github', 'client_id' => 'a',
        ], self::APP);

        $second = ProviderConfig::fromArray('personal', [
            'driver' => 'github', 'client_id' => 'b',
        ], self::APP);

        // Nobody is the same person across two separate logins just because both
        // happen to speak to GitHub.
        self::assertSame('oauth:work', $first->userInfo?->issuer);
        self::assertSame('oauth:personal', $second->userInfo?->issuer);
    }

    public function testAnUnknownProviderIsToldExactlyWhatIsMissing(): void
    {
        $this->assertConfigurationError(
            'auth:logins:acme:issuer',
            fn() => ProviderConfig::fromArray('acme', ['client_id' => 'abc'], self::APP),
        );
    }

    public function testAGenericIssuerBecomesADiscoveryUrl(): void
    {
        $provider = ProviderConfig::fromArray('acme', [
            'issuer'    => 'https://id.example.test/realms/main/',
            'client_id' => 'abc',
        ], self::APP);

        self::assertSame(
            'https://id.example.test/realms/main/.well-known/openid-configuration',
            $provider->discoveryUrl,
        );
    }

    public function testAMissingClientIdIsNamed(): void
    {
        $this->assertConfigurationError(
            'auth:logins:google:client_id',
            fn() => ProviderConfig::fromArray('google', [], self::APP),
        );
    }

    public function testAPublicClientNeedsNoSecret(): void
    {
        $provider = ProviderConfig::fromArray('google', ['client_id' => 'abc'], self::APP);

        self::assertNull($provider->clientSecret);
    }

    // ------------------------------------------------------------- Microsoft

    public function testMicrosoftDemandsAnAccountRange(): void
    {
        $this->assertConfigurationError(
            'auth:logins:microsoft:tenant',
            fn() => ProviderConfig::fromArray('microsoft', ['client_id' => 'abc'], self::APP),
        );
    }

    public function testASingleTenantPinsTheIssuerByItself(): void
    {
        $provider = ProviderConfig::fromArray('microsoft', [
            'client_id' => 'abc',
            'tenant'    => '8f3a1c94-0000-0000-0000-000000000000',
        ], self::APP);

        self::assertNull($provider->allowedTenants, 'one named tenant needs no list');
        self::assertStringContainsString('8f3a1c94-0000-0000-0000-000000000000', $provider->discoveryUrl);
    }

    public function testEveryOrganisationIsNeverOpenedQuietly(): void
    {
        foreach (['common', 'organizations', 'consumers'] as $tenant) {
            $this->assertConfigurationError(
                'auth:logins:microsoft:allowed_tenants',
                fn() => ProviderConfig::fromArray('microsoft', [
                    'client_id' => 'abc',
                    'tenant'    => $tenant,
                ], self::APP),
                'tenant: ' . $tenant,
            );
        }
    }

    public function testAnExplicitListOpensItDeliberately(): void
    {
        $provider = $this->multiTenant(['tenant-a', 'tenant-b']);

        self::assertSame(['tenant-a', 'tenant-b'], $provider->allowedTenants);
        self::assertSame(
            'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
            $provider->discoveryUrl,
        );
    }

    public function testATemplatedIssuerIsResolvedFromTheTokensOwnTenant(): void
    {
        $this->multiTenant(['tenant-a'])->verifyIssuer(
            'https://login.microsoftonline.com/{tenantid}/v2.0',
            'https://login.microsoftonline.com/tenant-a/v2.0',
            ['tid' => 'tenant-a'],
        );

        $this->addToAssertionCount(1);
    }

    public function testATenantOutsideTheListIsRefused(): void
    {
        $this->assertOAuthReason('tenant_not_allowed', fn() => $this->multiTenant(['tenant-a'])->verifyIssuer(
            'https://login.microsoftonline.com/{tenantid}/v2.0',
            'https://login.microsoftonline.com/tenant-z/v2.0',
            ['tid' => 'tenant-z'],
        ));
    }

    public function testAWildcardAcceptsEveryTenantButStillChecksTheIssuer(): void
    {
        $provider = $this->multiTenant(['*']);

        $provider->verifyIssuer(
            'https://login.microsoftonline.com/{tenantid}/v2.0',
            'https://login.microsoftonline.com/tenant-z/v2.0',
            ['tid' => 'tenant-z'],
        );

        $this->assertOAuthReason('issuer_mismatch', fn() => $provider->verifyIssuer(
            'https://login.microsoftonline.com/{tenantid}/v2.0',
            'https://evil.test/tenant-z/v2.0',
            ['tid' => 'tenant-z'],
        ));
    }

    public function testATemplatedIssuerWithoutATenantClaimIsRefused(): void
    {
        $this->assertOAuthReason('issuer_mismatch', fn() => $this->multiTenant(['*'])->verifyIssuer(
            'https://login.microsoftonline.com/{tenantid}/v2.0',
            'https://login.microsoftonline.com/tenant-a/v2.0',
            [],
        ));
    }

    // -------------------------------------------------------- Callback URLs

    public function testAnExplicitCallbackWins(): void
    {
        $provider = ProviderConfig::fromArray('google', [
            'client_id'    => 'abc',
            'callback_url' => 'https://other.example.test/finish',
        ], self::APP);

        self::assertSame('https://other.example.test/finish', $provider->redirectUri);
    }

    public function testAPlainHttpCallbackIsRefusedUnlessItIsLoopback(): void
    {
        $this->assertConfigurationError('must be https', fn() => ProviderConfig::fromArray('google', [
            'client_id'    => 'abc',
            'callback_url' => 'http://app.example.test/auth/google/callback',
        ], self::APP));

        $local = ProviderConfig::fromArray('google', [
            'client_id'    => 'abc',
            'callback_url' => 'http://localhost:8080/auth/google/callback',
        ], self::APP);

        self::assertSame('http://localhost:8080/auth/google/callback', $local->redirectUri);
    }

    // ------------------------------------------------------------- Machinery

    /** @param list<string> $allowed */
    private function multiTenant(array $allowed): ProviderConfig
    {
        return ProviderConfig::fromArray('microsoft', [
            'client_id'       => 'abc',
            'tenant'          => 'common',
            'allowed_tenants' => $allowed,
        ], self::APP);
    }

    private function assertConfigurationError(string $needle, callable $run, string $because = ''): void
    {
        try {
            $run();
        } catch (ConfigurationException $e) {
            self::assertStringContainsString($needle, $e->getMessage(), $because);
            return;
        }

        self::fail('Expected a ConfigurationException mentioning "' . $needle . '". ' . $because);
    }

    private function assertOAuthReason(string $reason, callable $run): void
    {
        try {
            $run();
        } catch (OAuthException $e) {
            self::assertSame($reason, $e->reason, $e->getMessage());
            return;
        }

        self::fail('Expected an OAuthException with reason "' . $reason . '".');
    }
}
