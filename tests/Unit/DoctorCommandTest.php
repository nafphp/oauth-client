<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Client\Commands\DoctorCommand;
use Naf\OAuth\Client\Token\Cipher;
use Tests\CommandTestCase;
use Tests\Fixtures\AccountSource;
use Tests\Fixtures\FakeHttp;
use Tests\Fixtures\User;

use function Naf\app;

/**
 * What "naf oauth:doctor" says about a setup, and what it refuses to say.
 *
 * Its whole value is that somebody can act on the report without reading the
 * code, which makes a misleading line worse than a missing one: being told to
 * run a migration that has already run sends a person looking in the wrong
 * place, and they believe it because the command sounded certain.
 */
final class DoctorCommandTest extends CommandTestCase
{
    private const string ISSUER = 'https://id.example.test';

    public function testAHealthySetupSaysSoAndSucceeds(): void
    {
        $this->healthy();

        $result = $this->execute(new DoctorCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('Ready to sign people in.', $result->output);
        self::assertStringNotContainsString('!', $result->output, 'nothing should be flagged');
    }

    public function testItReportsTheThingsSomebodyWouldOtherwiseGuessAt(): void
    {
        $this->healthy();

        $result = $this->execute(new DoctorCommand());

        self::assertNotNull($result->line('naf/auth'));
        self::assertNotNull($result->line('public_url'));
        self::assertNotNull($result->line('UserInterface'));
        self::assertNotNull($result->line('oauth_identities'));
        self::assertStringContainsString('belongs to ' . self::ISSUER, (string) $result->line('metadata'));
    }

    public function testItPrintsTheCallbackUrlTheApplicationWillActuallySend(): void
    {
        $this->healthy(['callback_url' => 'https://app.example.test/sso/acme/return']);

        $result = $this->execute(new DoctorCommand());

        self::assertStringContainsString('https://app.example.test/sso/acme/return', (string) $result->line('callback'));
    }

    public function testAnUnreachableProviderIsAProblem(): void
    {
        $http = $this->healthy();
        $http->on('GET', self::ISSUER . '/.well-known/openid-configuration', 'nope', 500);

        $result = $this->execute(new DoctorCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('metadata_unavailable', $result->output);
    }

    public function testAMissingPublicUrlIsAProblem(): void
    {
        $this->healthy(publicUrl: null);

        $result = $this->execute(new DoctorCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('MISSING', (string) $result->line('public_url'));
    }

    public function testAProviderNobodyAskedIsNotReportedAsHavingAnswered(): void
    {
        // A provider without OpenID Connect is never contacted here: its endpoints
        // come from the configuration and its issuer is one we assigned. A green
        // "belongs to …" would read as proof that it answered.
        $http = $this->healthy([
            'issuer'        => null,
            'authorize_url' => 'https://plain.example.test/authorize',
            'token_url'     => 'https://plain.example.test/token',
            'userinfo_url'  => 'https://plain.example.test/me',
        ]);
        $http->on('GET', 'https://plain.example.test/me', ['id' => '1']);

        $result = $this->execute(new DoctorCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('no discovery document', (string) $result->line('metadata'));
        self::assertStringNotContainsString('belongs to', $result->output);
    }

    // ------------------------------------------------------------ Token storage

    public function testWithoutTokenStorageItSaysNothingIsKept(): void
    {
        $this->healthy();

        $result = $this->execute(new DoctorCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('off', (string) $result->line('oauth:tokens:store'));
        self::assertNull($result->line('ext-sodium'), 'nothing to check when nothing is kept');
    }

    public function testWithTokenStorageItSaysSoAndChecksWhatItNeeds(): void
    {
        // It used to say so only when storage was off, leaving the enabled case
        // to be inferred from the lines that followed.
        $this->healthy(tokens: ['store' => true, 'key' => Cipher::generateKey()]);

        $result = $this->execute(new DoctorCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('on', (string) $result->line('oauth:tokens:store'));
        self::assertStringContainsString('loaded', (string) $result->line('ext-sodium'));
        self::assertStringContainsString('set', (string) $result->line('oauth:tokens:key'));
        self::assertStringContainsString('present', (string) $result->line('oauth_provider_tokens'));
    }

    public function testAMissingKeyIsNotReportedAsAMissingTable(): void
    {
        // The store cannot be built without a key, so probing the table fails for
        // a reason that has nothing to do with the table. Reporting it as missing
        // sent people off to run a migration that had already run.
        $this->healthy(tokens: ['store' => true]);

        $result = $this->execute(new DoctorCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('oauth:tokens:key', (string) $result->line('oauth:tokens:key'));
        self::assertNull($result->line('oauth_provider_tokens'), 'the table is not the problem here');
        self::assertStringNotContainsString('db:migrate', $result->output);
    }

    public function testItSaysHowToMakeAKeyWithoutEverPrintingOne(): void
    {
        $key = Cipher::generateKey();

        $this->healthy(tokens: ['store' => true, 'key' => $key]);

        $result = $this->execute(new DoctorCommand());

        self::assertStringNotContainsString($key, $result->output);
        self::assertStringNotContainsString('client_secret', $result->output);
    }

    public function testWithoutAKeyItSaysHowToMakeOne(): void
    {
        $this->healthy(tokens: ['store' => true]);

        self::assertStringContainsString('random_bytes(32)', $this->execute(new DoctorCommand())->output);
    }

    // --------------------------------------------------------------- Machinery

    /**
     * @param array<string, string> $login Extra settings for the configured login.
     * @param array<string, mixed> $tokens
     */
    private function healthy(
        array $login = [],
        array $tokens = [],
        ?string $publicUrl = 'https://app.example.test',
    ): FakeHttp {
        $http = $this->provider();

        $this->database();
        app()->container()->set(AccountSource::class, new AccountSource());

        $this->configure(
            $tokens === [] ? [] : ['tokens' => $tokens],
            auth: [
                'session'   => false,
                'users'     => ['model' => User::class],
                'providers' => ['users' => AccountSource::class],
                'logins'    => ['acme' => $login + ['issuer' => self::ISSUER, 'client_id' => 'abc']],
            ],
            publicUrl: $publicUrl,
        );

        $this->boot();

        return $http;
    }
}
