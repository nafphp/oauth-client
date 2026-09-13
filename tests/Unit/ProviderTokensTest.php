<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Client\Core\{Callback, Flow, IdToken, Metadata, UserInfo};
use Naf\OAuth\Client\Exception\OAuthException;
use Naf\OAuth\Client\Provider\Presets;
use Naf\OAuth\Client\Provider\ProviderConfig;
use Naf\OAuth\Client\Token\ProviderToken;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\{ArrayTransactions, FakeHttp, Signer};

/**
 * What a provider actually handed out, as opposed to what it was asked for.
 *
 * The distinction is the whole point: an application that records the request
 * believes it has permissions nobody granted, and finds out as a 403 from an API
 * that will not explain itself.
 */
final class ProviderTokensTest extends TestCase
{
    private const string ISSUER     = 'https://id.example.test';
    private const string DISCOVERY  = self::ISSUER . '/.well-known/openid-configuration';
    private const string JWKS       = self::ISSUER . '/jwks';
    private const string TOKEN      = self::ISSUER . '/token';
    private const string REVOKE     = self::ISSUER . '/revoke';
    private const string CLIENT_ID  = 'client-abc';

    private static ?Signer $signer = null;

    private FakeHttp $http;
    private ArrayTransactions $transactions;
    private string $cache;

    protected function setUp(): void
    {
        self::$signer ??= new Signer();

        $this->cache = sys_get_temp_dir() . '/naf-oauth-' . bin2hex(random_bytes(6));
        $this->http  = new FakeHttp();
        $this->http->on('GET', self::DISCOVERY, $this->document());
        $this->http->on('GET', self::JWKS, self::$signer->jwks());

        $this->transactions = new ArrayTransactions();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->cache . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->cache);
    }

    // --------------------------------------------- What came back, and its scope

    public function testTheGrantedScopeIsWhatTheProviderSaidNotWhatWasAsked(): void
    {
        // Somebody unticked "profile" on the consent screen. RFC 6749 §5.1 is why
        // the answer says so at all.
        $token = $this->finish(['scope' => 'openid email']);

        self::assertSame(['openid', 'email'], $token->scope);
        self::assertFalse($token->grants('profile'), 'a permission nobody granted is not held');
        self::assertTrue($token->grants('openid', 'email'));
    }

    public function testSilenceAboutTheScopeMeansWhatWasAsked(): void
    {
        // The same paragraph: a provider states the scope only when it differs.
        $token = $this->finish([]);

        self::assertSame(['openid', 'email', 'profile'], $token->scope);
    }

    public function testACommaDelimitedScopeIsReadToo(): void
    {
        // GitHub answers with commas where the RFC says spaces.
        $token = $this->finish(['scope' => 'read:user,user:email']);

        self::assertSame(['read:user', 'user:email'], $token->scope);
    }

    public function testALifetimeIsRecordedAsAPointInTime(): void
    {
        $token = $this->finish(['expires_in' => 3600]);

        self::assertNotNull($token->expiresAt);
        self::assertEqualsWithDelta(time() + 3600, $token->expiresAt, 5);
        self::assertFalse($token->hasExpired());
    }

    public function testALifetimeStatedAsATextIsStillALifetime(): void
    {
        self::assertNotNull($this->finish(['expires_in' => '600'])->expiresAt);
    }

    public function testAProviderThatNamesNoLifetimeIsNotAssumedToMeanForever(): void
    {
        $token = $this->finish([]);

        self::assertNull($token->expiresAt);
        self::assertFalse($token->hasExpired(), 'nothing is known, so nothing is renewed on a guess');
    }

    public function testTheRefreshTokenIsKept(): void
    {
        self::assertSame('rt-1', $this->finish(['refresh_token' => 'rt-1'])->refreshToken);
    }

    public function testAnAnswerWithoutAnAccessTokenCarriesNothingToStore(): void
    {
        // An OpenID Connect login that only proves who somebody is. There is
        // nothing here to call an API with, and nothing to keep.
        $started = $this->start($this->flow());

        $this->http->on('POST', self::TOKEN, [
            'token_type' => 'Bearer',
            'id_token'   => self::$signer->sign($this->claims($started['nonce'])),
        ]);

        $callback = $this->flow()->callback(['code' => 'c', 'state' => $started['state']]);

        self::assertNull($callback->token);
    }

    public function testNeitherTokenSurvivesBeingPrinted(): void
    {
        $printed = print_r($this->finish(['refresh_token' => 'rt-1']), true);

        self::assertStringNotContainsString('at-1', $printed);
        self::assertStringNotContainsString('rt-1', $printed);
        self::assertStringContainsString('[redacted]', $printed);
    }

    // ------------------------------------------------------------ Offline access

    public function testOfflineAccessIsOnlyAskedForWhereSomethingWillKeepIt(): void
    {
        self::assertSame(
            'openid email profile',
            $this->parameters($this->flow(offline: false)->authorizationUrl())['scope'],
        );

        self::assertSame(
            'openid email profile offline_access',
            $this->parameters($this->flow(offline: true)->authorizationUrl())['scope'],
            'OpenID Connect Core §11 spells it as a scope',
        );
    }

    public function testGoogleIsAskedTheWayGoogleWantsToBeAsked(): void
    {
        $google = ProviderConfig::fromArray('google', ['client_id' => 'x'], 'https://app.example.test');

        // Google predates the standard spelling: a request parameter, and the
        // scope would be rejected.
        self::assertNull($google->offlineScope);
        self::assertSame(['access_type' => 'offline'], $google->offlineParams);
        self::assertArrayHasKey('prompt', $google->grantParams);
    }

    public function testEveryPresetSaysHowToAskAgain(): void
    {
        foreach (Presets::names() as $name) {
            $preset = Presets::get($name) ?? [];

            self::assertArrayHasKey('grant_params', $preset, $name . ' cannot be asked for more');
        }
    }

    // ------------------------------------------------------------- Asking for more

    public function testAGrantAsksForTheExtraScopesOnTopOfTheLoginOnes(): void
    {
        $url = $this->flow()->grantUrl(['https://api.example.test/calendar'], 'database', '42');

        self::assertSame(
            'openid email profile https://api.example.test/calendar offline_access',
            $this->parameters($url)['scope'],
        );
    }

    public function testAScopeIsNotAskedForTwice(): void
    {
        $url = $this->flow()->grantUrl(['email', 'https://api.example.test/calendar'], 'database', '42');

        self::assertSame(
            'openid email profile https://api.example.test/calendar offline_access',
            $this->parameters($url)['scope'],
        );
    }

    public function testAGrantHasToSayWhatItIsFor(): void
    {
        $this->expectReason('no_scopes', fn() => $this->flow()->grantUrl([], 'database', '42'));
    }

    public function testAGrantNeedsSomebodyToGrantIt(): void
    {
        $this->expectReason('no_initiator', fn() => $this->flow()->grantUrl(['calendar'], '', ''));
    }

    public function testAGrantComesBackAsALinkToTheSamePerson(): void
    {
        $url     = $this->flow()->grantUrl(['calendar'], 'database', '42');
        $started = $this->parameters($url);

        $this->http->on('POST', self::TOKEN, [
            'access_token' => 'at-1',
            'id_token'     => self::$signer->sign($this->claims($started['nonce'])),
        ]);

        $callback = $this->flow()->callback(['code' => 'c', 'state' => $started['state']]);

        self::assertTrue($callback->isLink());
        self::assertSame(['provider' => 'database', 'id' => '42'], $callback->initiator);
    }

    public function testWhatWasAskedForIncludesTheGrantWhenTheAnswerStaysSilent(): void
    {
        $url     = $this->flow()->grantUrl(['calendar'], 'database', '42');
        $started = $this->parameters($url);

        $this->http->on('POST', self::TOKEN, [
            'access_token' => 'at-1',
            'id_token'     => self::$signer->sign($this->claims($started['nonce'])),
        ]);

        $token = $this->flow()->callback(['code' => 'c', 'state' => $started['state']])->token;

        // The login's own scopes would have been the wrong fallback here: this
        // request asked for more, and the transaction is what remembered.
        self::assertNotNull($token);
        self::assertTrue($token->grants('calendar'));
    }

    // -------------------------------------------------------------------- Renewing

    public function testRenewingKeepsARefreshTokenTheProviderDidNotRotate(): void
    {
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-2', 'expires_in' => 3600]);

        $renewed = $this->flow()->refresh($this->stored(refreshToken: 'rt-1'));

        self::assertSame('at-2', $renewed->accessToken);
        self::assertSame('rt-1', $renewed->refreshToken, 'silence is not a withdrawal');
    }

    public function testARotatedRefreshTokenReplacesTheOldOne(): void
    {
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-2', 'refresh_token' => 'rt-2']);

        self::assertSame('rt-2', $this->flow()->refresh($this->stored(refreshToken: 'rt-1'))->refreshToken);
    }

    public function testAnAnswerThatOmitsTheScopeGrantedWhatItGrantedBefore(): void
    {
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-2']);

        $renewed = $this->flow()->refresh($this->stored(refreshToken: 'rt-1', scope: ['openid', 'calendar']));

        self::assertSame(['openid', 'calendar'], $renewed->scope);
    }

    public function testAWithdrawnGrantIsReportedAsNeedingConsentAgain(): void
    {
        // RFC 6749 §5.2: the refusal that means the refresh token is no longer one.
        $this->http->on('POST', self::TOKEN, ['error' => 'invalid_grant'], 400);

        $this->expectReason('consent_required', fn() => $this->flow()->refresh($this->stored(refreshToken: 'rt-1')));
    }

    public function testAnOutageIsNotAWithdrawnGrant(): void
    {
        $this->http->on('POST', self::TOKEN, ['error' => 'temporarily_unavailable'], 503);

        $this->expectReason('refresh_failed', fn() => $this->flow()->refresh($this->stored(refreshToken: 'rt-1')));
    }

    public function testThereIsNothingToRenewWithoutARefreshToken(): void
    {
        $this->expectReason('consent_required', fn() => $this->flow()->refresh($this->stored()));
    }

    // -------------------------------------------------------------------- Revoking

    public function testRevokingTellsTheProviderAboutBothTokens(): void
    {
        $this->http->on('POST', self::REVOKE, '');

        $this->flow()->revoke($this->stored(refreshToken: 'rt-1'));

        self::assertSame(2, $this->http->calls('POST', self::REVOKE));

        $body = $this->http->lastBody('POST', self::REVOKE);
        self::assertStringContainsString('token_type_hint=access_token', $body);
    }

    public function testAProviderWithNothingToRevokeAgainstIsNotAFailure(): void
    {
        $document = $this->document();
        unset($document['revocation_endpoint']);
        $this->http->on('GET', self::DISCOVERY, $document);

        $this->flow()->revoke($this->stored(refreshToken: 'rt-1'));

        self::assertSame(0, $this->http->calls('POST', self::REVOKE));
    }

    public function testAProviderThatRefusesARevocationDoesNotStopUsForgetting(): void
    {
        // RFC 7009 §2.2: a server may answer anything for a token it does not
        // know, and somebody signing out cannot act on that either way.
        $this->http->on('POST', self::REVOKE, ['error' => 'unsupported_token_type'], 400);

        $this->flow()->revoke($this->stored(refreshToken: 'rt-1'));

        self::assertSame(2, $this->http->calls('POST', self::REVOKE));
    }

    // --------------------------------------------------------------- Machinery

    private function flow(bool $offline = true): Flow
    {
        $metadata = new Metadata($this->http, $this->cache);

        return new Flow(
            provider: ProviderConfig::fromArray('acme', [
                'issuer'        => self::ISSUER,
                'client_id'     => self::CLIENT_ID,
                'client_secret' => 'shhh',
            ], 'https://app.example.test'),
            http: $this->http,
            transactions: $this->transactions,
            metadata: $metadata,
            idToken: new IdToken($metadata),
            userInfo: new UserInfo($this->http),
            afterLogin: '/dashboard',
            offlineAccess: $offline,
        );
    }

    /** @param array<string, mixed> $extra Added to the token endpoint's answer. */
    private function finish(array $extra): ProviderToken
    {
        $flow    = $this->flow(offline: false);
        $started = $this->start($flow);

        $this->http->on('POST', self::TOKEN, $extra + [
            'access_token' => 'at-1',
            'token_type'   => 'Bearer',
            'id_token'     => self::$signer->sign($this->claims($started['nonce'])),
        ]);

        $token = $flow->callback(['code' => 'the-code', 'state' => $started['state']])->token;

        self::assertInstanceOf(ProviderToken::class, $token);

        return $token;
    }

    /** @return array{state:string,nonce:string} */
    private function start(Flow $flow): array
    {
        $parameters = $this->parameters($flow->authorizationUrl());

        return ['state' => $parameters['state'], 'nonce' => $parameters['nonce']];
    }

    /** @param list<string> $scope */
    private function stored(?string $refreshToken = null, array $scope = ['openid']): ProviderToken
    {
        return new ProviderToken('acme', self::ISSUER, 'user-42', 'at-1', $refreshToken, $scope, time() - 1);
    }

    /** @return array<string,mixed> */
    private function claims(string $nonce): array
    {
        return [
            'iss'   => self::ISSUER,
            'sub'   => 'user-42',
            'aud'   => self::CLIENT_ID,
            'nonce' => $nonce,
            'iat'   => time(),
            'exp'   => time() + 600,
            'email' => 'somebody@example.test',
        ];
    }

    /** @return array<string,mixed> */
    private function document(): array
    {
        return [
            'issuer'                                => self::ISSUER,
            'authorization_endpoint'                => self::ISSUER . '/authorize',
            'token_endpoint'                        => self::TOKEN,
            'revocation_endpoint'                   => self::REVOKE,
            'jwks_uri'                              => self::JWKS,
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];
    }

    /** @return array<string,string> */
    private function parameters(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);

        /** @var array<string,string> $parameters */
        return $parameters;
    }

    private function expectReason(string $reason, callable $run): void
    {
        try {
            $run();
        } catch (OAuthException $e) {
            self::assertSame($reason, $e->reason, $e->getMessage());

            return;
        }

        self::fail('Expected ' . $reason . ', but nothing was refused.');
    }
}
