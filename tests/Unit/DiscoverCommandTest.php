<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Client\Commands\DiscoverCommand;
use Tests\CommandTestCase;

/**
 * What "nix oauth:discover" tells somebody setting a provider up.
 *
 * It exists to answer two questions before anybody tries to sign in: does this
 * configuration resolve, and which callback URL has to be registered. Both
 * answers are only worth anything if they come from the same place the
 * application will read at run time — which is the whole point of the first test
 * here, and was the bug that prompted these.
 */
final class DiscoverCommandTest extends CommandTestCase
{
    private const string ISSUER = 'https://id.example.test';

    public function testALoginConfiguredTheDocumentedWayIsFound(): void
    {
        // auth:logins is where the README puts logins. Reading them from
        // anywhere else made this report "client_id is required" about a
        // client_id that was plainly there.
        $this->provider();
        $this->configure(auth: $this->logins(['client_id' => 'abc']));
        $this->boot();

        $result = $this->execute(new DiscoverCommand(), ['acme']);

        $this->assertSucceeded($result);
        self::assertStringContainsString(self::ISSUER, $result->output);
        self::assertStringNotContainsString('is required', $result->output);
    }

    public function testTheOlderConfigurationStillWorks(): void
    {
        $this->provider();
        $this->configure(['providers' => ['acme' => ['issuer' => self::ISSUER, 'client_id' => 'abc']]]);
        $this->boot();

        $this->assertSucceeded($this->execute(new DiscoverCommand(), ['acme']));
    }

    public function testItPrintsTheCallbackUrlTheApplicationWillActuallySend(): void
    {
        // Derived from the public URL it would look right; stated explicitly it
        // would not, and nobody re-checks a URL that was registered once.
        $this->provider();
        $this->configure(auth: $this->logins([
            'client_id'    => 'abc',
            'callback_url' => 'https://app.example.test/sso/acme/return',
        ]));
        $this->boot();

        $result = $this->execute(new DiscoverCommand(), ['acme']);

        self::assertStringContainsString('https://app.example.test/sso/acme/return', $result->output);
        self::assertStringNotContainsString('/auth/acme/callback', $result->output);
    }

    public function testItReportsWhatToRegisterAndWhatItFound(): void
    {
        $this->provider();
        $this->configure(auth: $this->logins(['client_id' => 'abc']));
        $this->boot();

        $result = $this->execute(new DiscoverCommand(), ['acme']);

        self::assertSame(self::ISSUER, $result->value('Issuer'));
        self::assertSame(self::ISSUER . '/authorize', $result->value('Authorization'));
        self::assertSame(self::ISSUER . '/token', $result->value('Token'));
        self::assertSame('1', $result->value('Signing keys'));
    }

    public function testEveryLoginIsCheckedWhenNoneIsNamed(): void
    {
        $this->provider();
        $this->configure(auth: ['session' => false, 'logins' => [
            'acme'  => ['issuer' => self::ISSUER, 'client_id' => 'abc'],
            'other' => ['issuer' => self::ISSUER, 'client_id' => 'def'],
        ]]);
        $this->boot();

        $result = $this->execute(new DiscoverCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('/auth/acme/callback', $result->output);
        self::assertStringContainsString('/auth/other/callback', $result->output);
    }

    public function testOneBrokenLoginFailsTheRunWithoutHidingTheHealthyOnes(): void
    {
        $http = $this->provider();
        $http->on('GET', 'https://gone.example.test/.well-known/openid-configuration', 'nope', 500);

        $this->configure(auth: ['session' => false, 'logins' => [
            'acme' => ['issuer' => self::ISSUER, 'client_id' => 'abc'],
            'gone' => ['issuer' => 'https://gone.example.test', 'client_id' => 'def'],
        ]]);
        $this->boot();

        $result = $this->execute(new DiscoverCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('/auth/acme/callback', $result->output, 'the working one is still reported');
        self::assertStringContainsString('gone.example.test', $result->output);
    }

    public function testAProviderWithoutOpenIdConnectIsNotReportedAsBroken(): void
    {
        // It publishes no key set, and asking for one anyway used to be a fatal
        // rather than an answer.
        $http = $this->provider();
        $http->on('GET', 'https://plain.example.test/me', ['id' => '1']);

        $this->configure(auth: ['session' => false, 'logins' => ['plain' => [
            'client_id'     => 'abc',
            'authorize_url' => 'https://plain.example.test/authorize',
            'token_url'     => 'https://plain.example.test/token',
            'userinfo_url'  => 'https://plain.example.test/me',
        ]]]);
        $this->boot();

        $result = $this->execute(new DiscoverCommand(), ['plain']);

        $this->assertSucceeded($result);
        self::assertStringContainsString('does not speak OpenID Connect', $result->output);
    }

    public function testAnUnknownLoginNamesTheOnesThatExist(): void
    {
        $this->provider();
        $this->configure(auth: $this->logins(['client_id' => 'abc']));
        $this->boot();

        $result = $this->execute(new DiscoverCommand(), ['nowhere']);

        $this->assertFailed($result);
        self::assertStringContainsString('acme', $result->output);
    }

    public function testWithoutAnyLoginItSaysWhereOneWouldGo(): void
    {
        $this->provider();
        $this->configure();
        $this->boot();

        $result = $this->execute(new DiscoverCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('auth:logins', $result->output);
    }

    // --------------------------------------------------------------- Machinery

    /**
     * @param array<string, string> $settings
     * @return array<string, mixed>
     */
    private function logins(array $settings): array
    {
        return ['session' => false, 'logins' => ['acme' => ['issuer' => self::ISSUER] + $settings]];
    }
}
