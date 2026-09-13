<?php

declare(strict_types=1);

namespace Tests\Unit;

use NixPHP\OAuth\Client\Core\{Callback, Flow, IdToken, Metadata, UserInfo};
use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Provider\ProviderConfig;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\{ArrayTransactions, FakeHttp, Signer};

/** Starting a login, and what the callback accepts — above all, what it does not. */
final class FlowTest extends TestCase
{
    private const string ISSUER    = 'https://id.example.test';
    private const string DISCOVERY = self::ISSUER . '/.well-known/openid-configuration';
    private const string JWKS      = self::ISSUER . '/jwks';
    private const string TOKEN     = self::ISSUER . '/token';
    private const string CLIENT_ID = 'client-abc';

    private static ?Signer $signer = null;

    private FakeHttp $http;
    private ArrayTransactions $transactions;
    private Flow $flow;
    private string $cache;

    protected function setUp(): void
    {
        self::$signer ??= new Signer();

        $this->cache = sys_get_temp_dir() . '/nixphp-oauth-' . bin2hex(random_bytes(6));
        $this->http  = new FakeHttp();

        $this->http->on('GET', self::DISCOVERY, $this->document());
        $this->http->on('GET', self::JWKS, self::$signer->jwks());

        $this->transactions = new ArrayTransactions();
        $metadata           = new Metadata($this->http, $this->cache);

        $this->flow = new Flow(
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
        );
    }

    protected function tearDown(): void
    {
        foreach (glob($this->cache . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->cache);
    }

    // ------------------------------------------------------------------- Start

    public function testTheAuthorizationUrlCarriesEverythingTheProtocolNeeds(): void
    {
        $parameters = $this->parameters($this->flow->authorizationUrl());

        self::assertSame('code', $parameters['response_type']);
        self::assertSame(self::CLIENT_ID, $parameters['client_id']);
        self::assertSame('https://app.example.test/auth/acme/callback', $parameters['redirect_uri']);
        self::assertSame('S256', $parameters['code_challenge_method']);
        self::assertNotSame('', $parameters['code_challenge']);
        self::assertNotSame('', $parameters['state']);
        self::assertNotSame('', $parameters['nonce']);
        self::assertArrayNotHasKey('code_verifier', $parameters, 'the verifier never leaves the server');
    }

    public function testTheChallengeIsTheHashOfTheStoredVerifier(): void
    {
        $parameters = $this->parameters($this->flow->authorizationUrl());
        $verifier   = $this->transactions->pending[$parameters['state']]['verifier'];

        self::assertSame(
            rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            $parameters['code_challenge'],
        );
    }

    public function testEveryLoginGetsItsOwnStateAndNonce(): void
    {
        $first  = $this->parameters($this->flow->authorizationUrl());
        $second = $this->parameters($this->flow->authorizationUrl());

        self::assertNotSame($first['state'], $second['state']);
        self::assertNotSame($first['nonce'], $second['nonce']);
        self::assertCount(2, $this->transactions->pending, 'both tabs stay pending');
    }

    public function testAnExternalRedirectTargetIsRefused(): void
    {
        foreach (['https://evil.test/', '//evil.test/', '/\\evil.test', ''] as $target) {
            $parameters = $this->parameters($this->flow->authorizationUrl($target));

            self::assertSame(
                '/dashboard',
                $this->transactions->pending[$parameters['state']]['redirect'],
                'refused: ' . $target,
            );
        }
    }

    public function testALocalRedirectTargetIsKept(): void
    {
        $parameters = $this->parameters($this->flow->authorizationUrl('/projects/7'));

        self::assertSame('/projects/7', $this->transactions->pending[$parameters['state']]['redirect']);
    }

    public function testLinkingRecordsWhoStartedIt(): void
    {
        $parameters = $this->parameters($this->flow->linkUrl('database', '42'));
        $pending    = $this->transactions->pending[$parameters['state']];

        self::assertSame(Callback::LINK, $pending['purpose']);
        self::assertSame(['provider' => 'database', 'id' => '42'], $pending['initiator']);
    }

    public function testLinkingNeedsSomebodyToLinkTo(): void
    {
        $this->expectExceptionReason('no_initiator', fn() => $this->flow->linkUrl('database', ''));
    }

    public function testTheFlowHandsOutTheCallbackUrlItWillActuallySend(): void
    {
        // Whatever prints a URL for somebody to register at the provider has to
        // print this one. Rebuilding it from the public URL looks identical until
        // an application states its own, and then it is quietly wrong in the one
        // place nobody checks twice.
        $flow = new Flow(
            provider: ProviderConfig::fromArray('acme', [
                'issuer'       => self::ISSUER,
                'client_id'    => self::CLIENT_ID,
                'callback_url' => 'https://app.example.test/sso/acme/return',
            ], 'https://app.example.test'),
            http: $this->http,
            transactions: $this->transactions,
            metadata: new Metadata($this->http, $this->cache),
            idToken: new IdToken(new Metadata($this->http, $this->cache)),
            userInfo: new UserInfo($this->http),
        );

        self::assertSame('https://app.example.test/sso/acme/return', $flow->redirectUri());
        self::assertSame('https://app.example.test/auth/acme/callback', $this->flow->redirectUri());
    }

    // ---------------------------------------------------------------- Callback

    public function testAVerifiedCallbackYieldsTheExternalIdentity(): void
    {
        $callback = $this->finish();

        self::assertTrue($callback->isLogin());
        self::assertSame('acme', $callback->identity->provider);
        self::assertSame(self::ISSUER, $callback->identity->issuer);
        self::assertSame('user-42', $callback->identity->subject);
        self::assertSame('alice@example.test', $callback->identity->email);
        self::assertTrue($callback->identity->emailVerified);
        self::assertSame('/dashboard', $callback->redirectTo);
    }

    public function testTheCodeIsExchangedWithPkceAndBasicAuthentication(): void
    {
        $this->finish();

        parse_str($this->http->lastBody('POST', self::TOKEN), $body);

        self::assertSame('authorization_code', $body['grant_type']);
        self::assertSame('https://app.example.test/auth/acme/callback', $body['redirect_uri']);
        self::assertNotSame('', $body['code_verifier']);
        self::assertArrayNotHasKey('client_secret', $body, 'the secret belongs in the header, not the body');

        $authorization = (string) $this->http->lastRequest('POST', self::TOKEN)?->getHeaderLine('Authorization');
        self::assertSame('Basic ' . base64_encode(self::CLIENT_ID . ':shhh'), $authorization);
    }

    public function testTwoParallelLoginsBothFinish(): void
    {
        $first  = $this->start();
        $second = $this->start();

        $one = $this->finishStarted($second, ['sub' => 'user-2']);
        $two = $this->finishStarted($first, ['sub' => 'user-1']);

        self::assertSame('user-2', $one->identity->subject);
        self::assertSame('user-1', $two->identity->subject, 'the first tab still works after the second finished');
    }

    public function testACallbackCannotBeReplayed(): void
    {
        $started = $this->start();
        $this->finishStarted($started);

        $this->expectExceptionReason('state_unknown', fn() => $this->flow->callback([
            'code'  => 'the-code',
            'state' => $started['state'],
        ]));
    }

    public function testAnUnknownStateIsRefused(): void
    {
        $this->expectExceptionReason('state_unknown', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => 'never-issued',
        ]));
    }

    public function testAMissingStateIsRefused(): void
    {
        $this->expectExceptionReason('state_missing', fn() => $this->flow->callback(['code' => 'the-code']));
    }

    public function testAMissingCodeIsRefusedAndStillConsumesTheLogin(): void
    {
        $started = $this->start();

        $this->expectExceptionReason('code_missing', fn() => $this->flow->callback(['state' => $started['state']]));
        self::assertSame([], $this->transactions->pending);
    }

    public function testAProviderErrorIsReportedAsSuch(): void
    {
        $started = $this->start();

        $this->expectExceptionReason('provider_error', fn() => $this->flow->callback([
            'error' => 'access_denied', 'state' => $started['state'],
        ]));
    }

    public function testAProviderErrorBelongsToAPendingLoginAndEndsIt(): void
    {
        $started = $this->start();

        $this->expectExceptionReason('provider_error', fn() => $this->flow->callback([
            'error' => 'access_denied', 'state' => $started['state'],
        ]));

        // Consumed like any other answer: a cancelled attempt does not sit pending
        // until it expires, and it cannot be replayed.
        self::assertSame([], $this->transactions->pending);
    }

    public function testAnErrorWithoutAPendingLoginIsRefusedBeforeItIsRead(): void
    {
        // Otherwise anybody can drive this endpoint by appending ?error= to it.
        $this->expectExceptionReason('state_unknown', fn() => $this->flow->callback([
            'error' => 'access_denied', 'state' => 'never-issued',
        ]));

        $this->expectExceptionReason('state_missing', fn() => $this->flow->callback([
            'error' => 'access_denied',
        ]));
    }

    public function testALoginStartedWithAnotherProviderIsRefused(): void
    {
        $started = $this->start();
        $this->transactions->pending[$started['state']]['provider'] = 'somebody-else';

        $this->expectExceptionReason('provider_mismatch', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testATokenEndpointRefusalIsReported(): void
    {
        $started = $this->start();
        $this->http->on('POST', self::TOKEN, ['error' => 'invalid_grant'], 400);

        $this->expectExceptionReason('token_request_failed', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testAResponseWithoutAnIdTokenIsRefused(): void
    {
        $started = $this->start();
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at', 'token_type' => 'Bearer']);

        $this->expectExceptionReason('id_token_missing', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    // ------------------------------------------------- What must never verify

    public function testAnIdTokenForAnotherLoginIsRefused(): void
    {
        $this->assertCallbackFails('nonce_mismatch', ['nonce' => 'some-other-login']);
    }

    public function testAnIdTokenFromAnotherIssuerIsRefused(): void
    {
        $this->assertCallbackFails('issuer_mismatch', ['iss' => 'https://evil.test']);
    }

    public function testAnIdTokenForAnotherApplicationIsRefused(): void
    {
        $this->assertCallbackFails('audience_mismatch', ['aud' => 'someone-elses-client']);
    }

    public function testSeveralAudiencesNeedAnAuthorisedPartyThatIsUs(): void
    {
        $this->assertCallbackFails('audience_mismatch', [
            'aud' => [self::CLIENT_ID, 'another-client'],
            'azp' => 'another-client',
        ]);
    }

    public function testAnExpiredIdTokenIsRefused(): void
    {
        $this->assertCallbackFails('id_token_invalid', ['exp' => time() - 3600, 'iat' => time() - 7200]);
    }

    public function testAnIdTokenWithoutASubjectIsRefused(): void
    {
        $this->assertCallbackFails('subject_missing', ['sub' => '']);
    }

    public function testATamperedIdTokenIsRefused(): void
    {
        $started = $this->start();

        $token    = self::$signer->sign($this->claims($started['nonce']));
        $segments = explode('.', $token);
        $payload  = json_decode((string) base64_decode(strtr($segments[1], '-_', '+/'), true), true);
        $payload['sub'] = 'somebody-else';
        $segments[1] = rtrim(strtr(base64_encode((string) json_encode($payload)), '+/', '-_'), '=');

        $this->http->on('POST', self::TOKEN, ['id_token' => implode('.', $segments)]);

        $this->expectExceptionReason('id_token_invalid', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testAnUnverifiedEmailIsNotReportedAsVerified(): void
    {
        // Providers have sent "true", 1 and "1" here. Only a real true counts.
        foreach (['true', 1, '1', false, null] as $value) {
            $callback = $this->finish(['email_verified' => $value]);

            self::assertFalse($callback->identity->emailVerified, 'email_verified: ' . var_export($value, true));
        }
    }

    // ------------------------------------------------------------ Key rotation

    public function testAKeyWeHaveNotSeenMakesUsReloadTheKeySet(): void
    {
        $this->finish();
        $before = $this->http->calls('GET', self::JWKS);

        // The provider rotates: a new key id, published only after the fact.
        $rotated = new Signer('key-2');
        $this->http->on('GET', self::JWKS, $rotated->jwks());

        $started = $this->start();
        $this->http->on('POST', self::TOKEN, ['id_token' => $rotated->sign($this->claims($started['nonce']))]);

        $callback = $this->flow->callback(['code' => 'the-code', 'state' => $started['state']]);

        self::assertSame('user-42', $callback->identity->subject);
        self::assertGreaterThan($before, $this->http->calls('GET', self::JWKS), 'the key set was reloaded');
    }

    // --------------------------------------------------------------- Machinery

    /** @return array{state:string,nonce:string} */
    private function start(): array
    {
        $parameters = $this->parameters($this->flow->authorizationUrl());

        return ['state' => $parameters['state'], 'nonce' => $parameters['nonce']];
    }

    /** @param array<string,mixed> $claimOverrides */
    private function finish(array $claimOverrides = []): Callback
    {
        return $this->finishStarted($this->start(), $claimOverrides);
    }

    /**
     * @param array{state:string,nonce:string} $started
     * @param array<string,mixed> $claimOverrides
     */
    private function finishStarted(array $started, array $claimOverrides = []): Callback
    {
        $this->http->on('POST', self::TOKEN, [
            'access_token' => 'at',
            'token_type'   => 'Bearer',
            'id_token'     => self::$signer->sign($claimOverrides + $this->claims($started['nonce'])),
        ]);

        return $this->flow->callback(['code' => 'the-code', 'state' => $started['state']]);
    }

    /** @param array<string,mixed> $claimOverrides */
    private function assertCallbackFails(string $reason, array $claimOverrides): void
    {
        $started = $this->start();

        $this->expectExceptionReason($reason, fn() => $this->finishStarted($started, $claimOverrides));
    }

    /** @return array<string,mixed> */
    private function claims(string $nonce): array
    {
        return [
            'iss'            => self::ISSUER,
            'sub'            => 'user-42',
            'aud'            => self::CLIENT_ID,
            'exp'            => time() + 300,
            'iat'            => time(),
            'nonce'          => $nonce,
            'email'          => 'alice@example.test',
            'email_verified' => true,
            'name'           => 'Alice',
        ];
    }

    /** @return array<string,mixed> */
    private function document(): array
    {
        return [
            'issuer'                                => self::ISSUER,
            'authorization_endpoint'                => self::ISSUER . '/authorize',
            'token_endpoint'                        => self::TOKEN,
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

    private function expectExceptionReason(string $reason, callable $run): void
    {
        try {
            $run();
        } catch (OAuthException $e) {
            self::assertSame($reason, $e->reason, $e->getMessage());
            return;
        }

        self::fail('Expected an OAuthException with reason "' . $reason . '".');
    }

    // ------------------------------------- A profile endpoint next to OIDC

    public function testAProfileEndpointDoesNotTurnOidcIntoPlainOAuth(): void
    {
        $flow = $this->flowWithProfile();

        $started = $this->parameters($flow->authorizationUrl());

        // Still OpenID Connect: an answer without an ID token is not an identity.
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-1', 'token_type' => 'Bearer']);

        $this->expectExceptionReason('id_token_missing', fn() => $flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testAProfileIsFoldedIntoTheVerifiedIdentity(): void
    {
        $flow    = $this->flowWithProfile();
        $started = $this->parameters($flow->authorizationUrl());

        $this->http->on('GET', self::ISSUER . '/userinfo', [
            'sub' => 'user-42', 'name' => 'Alice from the profile', 'locale' => 'de',
        ]);
        $this->http->on('POST', self::TOKEN, [
            'access_token' => 'at-1',
            'id_token'     => self::$signer->sign($this->claims($started['nonce'])),
        ]);

        $callback = $flow->callback(['code' => 'the-code', 'state' => $started['state']]);

        self::assertSame('user-42', $callback->identity->subject);
        self::assertSame('de', $callback->identity->claim('locale'), 'the profile filled this in');
        self::assertSame('Alice', $callback->identity->name, 'what was signed wins over what was fetched');
    }

    public function testAProfileAboutSomebodyElseIsRefused(): void
    {
        $flow    = $this->flowWithProfile();
        $started = $this->parameters($flow->authorizationUrl());

        $this->http->on('GET', self::ISSUER . '/userinfo', ['sub' => 'somebody-else']);
        $this->http->on('POST', self::TOKEN, [
            'access_token' => 'at-1',
            'id_token'     => self::$signer->sign($this->claims($started['nonce'])),
        ]);

        $this->expectExceptionReason('subject_mismatch', fn() => $flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    private function flowWithProfile(): Flow
    {
        $metadata = new Metadata($this->http, $this->cache);

        return new Flow(
            provider: ProviderConfig::fromArray('acme', [
                'issuer'        => self::ISSUER,
                'client_id'     => self::CLIENT_ID,
                'client_secret' => 'shhh',
                'userinfo_url'  => self::ISSUER . '/userinfo',
            ], 'https://app.example.test'),
            http: $this->http,
            transactions: $this->transactions,
            metadata: $metadata,
            idToken: new IdToken($metadata),
            userInfo: new UserInfo($this->http),
            afterLogin: '/dashboard',
        );
    }

    // ------------------------------------------------- Trusting the metadata

    public function testMetadataThatBelongsToSomebodyElseIsNotUsed(): void
    {
        // The configured issuer is the one thing the application actually stated.
        // Everything else arrives over the network and has to match it first.
        $this->http->on('GET', self::DISCOVERY, [
            'issuer'                 => 'https://evil.test',
            'authorization_endpoint' => 'https://evil.test/authorize',
            'token_endpoint'         => 'https://evil.test/token',
            'jwks_uri'               => 'https://evil.test/jwks',
        ]);

        $this->expectExceptionReason('issuer_mismatch', fn() => $this->flow->authorizationUrl());
    }

    public function testNoCredentialIsSentToAnAddressTheMetadataInvented(): void
    {
        $this->http->on('GET', self::DISCOVERY, [
            'issuer'                 => 'https://evil.test',
            'authorization_endpoint' => 'https://evil.test/authorize',
            'token_endpoint'         => 'https://evil.test/token',
        ]);

        $this->expectExceptionReason('issuer_mismatch', fn() => $this->flow->authorizationUrl());

        self::assertSame(0, $this->http->calls('POST', 'https://evil.test/token'));
    }

    // --------------------------------------------- What the ID token must say

    public function testAnIdTokenWithoutAnExpiryIsRefused(): void
    {
        $started = $this->start();
        $claims  = $this->claims($started['nonce']);
        unset($claims['exp']);

        $this->http->on('POST', self::TOKEN, ['id_token' => self::$signer->sign($claims)]);

        // The JWT library only checks exp when it is there, so a token that omits
        // it verifies and then never expires.
        $this->expectExceptionReason('id_token_invalid', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testAnIdTokenWithoutAnIssuedAtIsRefused(): void
    {
        $started = $this->start();
        $claims  = $this->claims($started['nonce']);
        unset($claims['iat']);

        $this->http->on('POST', self::TOKEN, ['id_token' => self::$signer->sign($claims)]);

        $this->expectExceptionReason('id_token_invalid', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testAnAuthorisedPartyThatIsNotUsIsRefusedWithOneAudienceToo(): void
    {
        // azp has to be us whenever it is present, not only when the audience list
        // happens to be longer than one.
        $this->assertCallbackFails('audience_mismatch', ['azp' => 'another-client']);
    }

    public function testAnAlgorithmTheProviderDoesNotPublishIsRefused(): void
    {
        // Published before anything is fetched: the document is cached on first use.
        $document = $this->document();
        $document['id_token_signing_alg_values_supported'] = ['ES256'];
        $this->http->on('GET', self::DISCOVERY, $document);

        $started = $this->start();

        $this->http->on('POST', self::TOKEN, ['id_token' => self::$signer->sign($this->claims($started['nonce']))]);

        $this->expectExceptionReason('id_token_invalid', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }

    public function testAnUnsignedTokenIsRefusedWhateverTheHeaderSays(): void
    {
        $started = $this->start();

        $claims  = $this->claims($started['nonce']);
        $header  = rtrim(strtr(base64_encode((string) json_encode(['alg' => 'none', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode((string) json_encode($claims)), '+/', '-_'), '=');

        $this->http->on('POST', self::TOKEN, ['id_token' => $header . '.' . $payload . '.']);

        $this->expectExceptionReason('id_token_invalid', fn() => $this->flow->callback([
            'code' => 'the-code', 'state' => $started['state'],
        ]));
    }
}
