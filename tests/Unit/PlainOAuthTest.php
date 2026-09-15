<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Client\Core\Callback;
use Naf\OAuth\Client\Core\Flow;
use Naf\OAuth\Client\Core\IdToken;
use Naf\OAuth\Client\Core\Metadata;
use Naf\OAuth\Client\Core\UserInfo;
use Naf\OAuth\Client\Exception\ConfigurationException;
use Naf\OAuth\Client\Exception\OAuthException;
use Naf\OAuth\Client\Provider\ProviderConfig;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\ArrayTransactions;
use Tests\Fixtures\FakeHttp;

/** Providers without OpenID Connect: named endpoints, no ID token, an API call instead. */
final class PlainOAuthTest extends TestCase
{
    private const string APP    = 'https://app.example.test';
    private const string TOKEN  = 'https://github.com/login/oauth/access_token';
    private const string USER   = 'https://api.github.com/user';
    private const string EMAILS = 'https://api.github.com/user/emails';

    private FakeHttp $http;
    private ArrayTransactions $transactions;
    private string $cache;

    protected function setUp(): void
    {
        $this->cache        = sys_get_temp_dir() . '/naf-oauth-plain-' . bin2hex(random_bytes(6));
        $this->http         = new FakeHttp();
        $this->transactions = new ArrayTransactions();

        // A profile without an address sends us to the address list, so there is
        // always one to answer. Tests that care about it say something else.
        $this->http->on('GET', self::EMAILS, []);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->cache . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->cache);
    }

    // -------------------------------------------------------- Configuration

    public function testTheGithubPresetNeedsNothingButCredentials(): void
    {
        $provider = $this->config();

        self::assertFalse($provider->isOidc());
        self::assertSame('GitHub', $provider->label);
        self::assertNull($provider->discoveryUrl, 'plain OAuth2 has no discovery document');
        self::assertSame('read:user user:email', $provider->scope);
        self::assertSame('body', $provider->clientAuth);
        self::assertSame('oauth:github', $provider->endpoints['issuer'] ?? null);
        self::assertSame('id', $provider->userInfo?->subjectField);
    }

    public function testAnUnknownProviderCanBeDescribedByHand(): void
    {
        $provider = ProviderConfig::fromArray('acme', [
            'client_id'     => 'abc',
            'authorize_url' => 'https://acme.test/authorize',
            'token_url'     => 'https://acme.test/token',
            'userinfo_url'  => 'https://acme.test/me',
            'subject_field' => 'user_id',
        ], self::APP);

        self::assertFalse($provider->isOidc());
        self::assertSame('oauth:acme', $provider->userInfo?->issuer);
        self::assertSame('user_id', $provider->userInfo?->subjectField);
        self::assertSame('basic', $provider->clientAuth, 'the standard default, unless the provider says otherwise');
    }

    public function testAHalfDescribedProviderIsNamedPrecisely(): void
    {
        try {
            ProviderConfig::fromArray('acme', [
                'client_id'    => 'abc',
                'userinfo_url' => 'https://acme.test/me',
            ], self::APP);
            self::fail('Expected a ConfigurationException.');
        } catch (ConfigurationException $e) {
            self::assertStringContainsString('auth:logins:acme:authorize_url', $e->getMessage());
        }
    }

    public function testAProviderThatIsNeitherKindExplainsBothWays(): void
    {
        try {
            ProviderConfig::fromArray('acme', ['client_id' => 'abc'], self::APP);
            self::fail('Expected a ConfigurationException.');
        } catch (ConfigurationException $e) {
            self::assertStringContainsString('auth:logins:acme:issuer', $e->getMessage());
            self::assertStringContainsString('auth:logins:acme:userinfo_url', $e->getMessage());
        }
    }

    // ---------------------------------------------------------------- Start

    public function testThereIsNoNonceWithoutAnIdTokenToBindItTo(): void
    {
        $parameters = $this->parameters($this->flow()->authorizationUrl());

        self::assertArrayNotHasKey('nonce', $parameters);
        self::assertSame('S256', $parameters['code_challenge_method'], 'PKCE still applies');
        self::assertSame('https://app.example.test/auth/github/callback', $parameters['redirect_uri']);
        self::assertSame(0, count($this->http->sent), 'no discovery document to fetch');
    }

    // ------------------------------------------------------------- Callback

    public function testTheIdentityComesFromTheProvidersApi(): void
    {
        $callback = $this->finish(['id' => 4711, 'name' => 'Alice', 'email' => 'alice@example.test']);

        self::assertSame('github', $callback->identity->provider);
        self::assertSame('oauth:github', $callback->identity->issuer);
        self::assertSame('4711', $callback->identity->subject, 'a numeric id becomes a string');
        self::assertSame('Alice', $callback->identity->name);
    }

    public function testTheSecretGoesWhereTheProviderDocumentsIt(): void
    {
        $this->finish(['id' => 1]);

        parse_str($this->http->lastBody('POST', self::TOKEN), $body);

        self::assertSame('shhh', $body['client_secret'] ?? null);
        self::assertSame('', (string) $this->http->lastRequest('POST', self::TOKEN)?->getHeaderLine('Authorization'));
    }

    public function testTheApiIsCalledWithTheTokenAndAUserAgent(): void
    {
        $this->finish(['id' => 1]);

        $request = $this->http->lastRequest('GET', self::USER);

        self::assertSame('Bearer at-123', $request?->getHeaderLine('Authorization'));
        self::assertNotSame('', (string) $request?->getHeaderLine('User-Agent'), 'some APIs refuse without one');
        self::assertSame('application/vnd.github+json', $request?->getHeaderLine('Accept'));
    }

    public function testAResponseWithoutAnAccessTokenIsRefused(): void
    {
        $started = $this->start();
        $this->http->on('POST', self::TOKEN, ['token_type' => 'Bearer']);

        $this->assertReason('access_token_missing', fn() => $this->flow()->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testARefusedApiCallIsNotAnIdentity(): void
    {
        $started = $this->start();
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-123']);
        $this->http->on('GET', self::USER, ['message' => 'Bad credentials'], 401);

        $this->assertReason('userinfo_unavailable', fn() => $this->flow()->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testAnAnswerWithoutTheIdentifyingFieldIsRefused(): void
    {
        $started = $this->start();
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-123']);
        $this->http->on('GET', self::USER, ['login' => 'alice']);

        $this->assertReason('subject_missing', fn() => $this->flow()->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    // ---------------------------------------------------- The address list

    public function testAHiddenAddressIsFetchedFromTheAddressList(): void
    {
        $this->http->on('GET', self::EMAILS, [
            ['email' => 'old@example.test',   'primary' => false, 'verified' => true],
            ['email' => 'alice@example.test', 'primary' => true,  'verified' => true],
        ]);

        $callback = $this->finish(['id' => 1, 'email' => null]);

        self::assertSame('alice@example.test', $callback->identity->email);
        self::assertTrue($callback->identity->emailVerified);
    }

    public function testAnUnverifiedAddressIsNotUsed(): void
    {
        $this->http->on('GET', self::EMAILS, [
            ['email' => 'alice@example.test', 'primary' => true, 'verified' => false],
        ]);

        $callback = $this->finish(['id' => 1, 'email' => null]);

        self::assertNull($callback->identity->email);
        self::assertFalse($callback->identity->emailVerified);
    }

    public function testAVerifiedAddressCountsEvenWhenItIsNotThePrimaryOne(): void
    {
        $this->http->on('GET', self::EMAILS, [
            ['email' => 'primary@example.test', 'primary' => true,  'verified' => false],
            ['email' => 'alice@example.test',   'primary' => false, 'verified' => true],
        ]);

        $callback = $this->finish(['id' => 1, 'email' => null]);

        self::assertSame('alice@example.test', $callback->identity->email);
    }

    public function testNoAddressIsNotAFailedLogin(): void
    {
        $this->http->on('GET', self::EMAILS, ['message' => 'Requires authentication'], 403);

        $callback = $this->finish(['id' => 1, 'email' => null]);

        self::assertSame('1', $callback->identity->subject);
        self::assertNull($callback->identity->email);
    }

    public function testAnAddressInTheProfileIsNotSecondGuessed(): void
    {
        $callback = $this->finish(['id' => 1, 'email' => 'public@example.test']);

        self::assertSame('public@example.test', $callback->identity->email);
        self::assertSame(0, $this->http->calls('GET', self::EMAILS), 'the list is only for a missing address');
        self::assertFalse($callback->identity->emailVerified, 'GitHub does not say, so we do not claim it');
    }

    public function testTheRawAnswerIsKeptAlongsideTheNormalisedClaims(): void
    {
        $callback = $this->finish(['id' => 1, 'login' => 'alice', 'company' => 'Acme']);

        self::assertSame('alice', $callback->identity->claim('login'));
        self::assertSame('Acme', $callback->identity->claim('company'));
    }

    // -------------------------------------------------------------- Machinery

    private function config(): ProviderConfig
    {
        return ProviderConfig::fromArray('github', [
            'client_id'     => 'client-abc',
            'client_secret' => 'shhh',
        ], self::APP);
    }

    private function flow(): Flow
    {
        $metadata = new Metadata($this->http, $this->cache);

        return new Flow(
            provider: $this->config(),
            http: $this->http,
            transactions: $this->transactions,
            metadata: $metadata,
            idToken: new IdToken($metadata),
            userInfo: new UserInfo($this->http),
            afterLogin: '/dashboard',
        );
    }

    /** @return array{state:string} */
    private function start(): array
    {
        return ['state' => $this->parameters($this->flow()->authorizationUrl())['state']];
    }

    /** @param array<string, mixed> $profile */
    private function finish(array $profile): Callback
    {
        $started = $this->start();

        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-123', 'token_type' => 'Bearer']);
        $this->http->on('GET', self::USER, $profile);

        return $this->flow()->callback(['code' => 'the-code', 'state' => $started['state']]);
    }

    /** @return array<string,string> */
    private function parameters(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);

        /** @var array<string,string> $parameters */
        return $parameters;
    }

    private function assertReason(string $reason, callable $run): void
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
