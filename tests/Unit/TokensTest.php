<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Auth\Auth;
use Naf\OAuth\Client\Account\Accounts;
use Naf\OAuth\Client\Core\Callback;
use Naf\OAuth\Client\Core\Flow;
use Naf\OAuth\Client\Core\IdToken;
use Naf\OAuth\Client\Core\Metadata;
use Naf\OAuth\Client\Core\OAuth;
use Naf\OAuth\Client\Core\UserInfo;
use Naf\OAuth\Client\Exception\OAuthException;
use Naf\OAuth\Client\Identity\ExternalIdentity;
use Naf\OAuth\Client\Provider\ProviderConfig;
use Naf\OAuth\Client\Token\ProviderToken;
use Naf\OAuth\Client\Token\Tokens;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Account;
use Tests\Fixtures\AccountSource;
use Tests\Fixtures\ArrayTransactions;
use Tests\Fixtures\FakeHttp;
use Tests\Fixtures\MemoryLinks;
use Tests\Fixtures\MemoryTokens;

/**
 * Handing out a token somebody can actually use.
 *
 * Two things are being separated here, and confusing them is the failure mode
 * this class exists to avoid: a person taking their permission back, which is
 * answered by asking again, and a provider being unreachable, which is answered
 * by waiting. Treating the second as the first would march people through a
 * consent screen that fixes nothing.
 */
final class TokensTest extends TestCase
{
    private const string ISSUER    = 'https://id.example.test';
    private const string DISCOVERY = self::ISSUER . '/.well-known/openid-configuration';
    private const string TOKEN     = self::ISSUER . '/token';
    private const string REVOKE    = self::ISSUER . '/revoke';

    private FakeHttp $http;
    private MemoryTokens $store;
    private MemoryLinks $links;
    private AccountSource $source;
    private Auth $auth;
    private Account $account;
    private string $cache;

    protected function setUp(): void
    {
        $this->cache = sys_get_temp_dir() . '/naf-oauth-' . bin2hex(random_bytes(6));
        $this->http  = new FakeHttp();
        $this->http->on('GET', self::DISCOVERY, [
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint'         => self::TOKEN,
            'revocation_endpoint'    => self::REVOKE,
            'jwks_uri'               => self::ISSUER . '/jwks',
        ]);

        $this->store  = new MemoryTokens();
        $this->links  = new MemoryLinks();
        $this->source = new AccountSource();
        $this->auth   = (new Auth())->addProvider('database', $this->source);

        $this->account = $this->source->add(new Account('42'));
        $this->auth->setIdentity($this->account, 'database');
        $this->links->link($this->external(), 'database', '42');
    }

    protected function tearDown(): void
    {
        foreach (glob($this->cache . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->cache);
    }

    // ------------------------------------------------------------ Handing one out

    public function testATokenThatStillWorksIsHandedOutUntouched(): void
    {
        $this->store->put($this->token(expiresAt: time() + 3600));

        $token = $this->tokens()->of('acme');

        self::assertNotNull($token);
        self::assertSame('at-1', $token->accessToken);
        self::assertSame(0, $this->http->calls('POST', self::TOKEN), 'nothing to renew, nobody to ask');
    }

    public function testAnExpiredTokenIsRenewedOnTheWayOut(): void
    {
        $this->store->put($this->token(expiresAt: time() - 1));
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-2', 'expires_in' => 3600]);

        $token = $this->tokens()->of('acme');

        self::assertNotNull($token);
        self::assertSame('at-2', $token->accessToken);
    }

    public function testTheRenewalIsWrittenBack(): void
    {
        // A rotated refresh token is worth exactly one use. Not storing it costs
        // somebody a consent screen the next time anything is asked of them.
        $this->store->put($this->token(expiresAt: time() - 1));
        $this->http->on('POST', self::TOKEN, ['access_token' => 'at-2', 'refresh_token' => 'rt-2']);

        $this->tokens()->of('acme');

        self::assertSame('rt-2', $this->store->find(self::ISSUER, 'user-1')?->refreshToken);
    }

    public function testAProviderNobodyLinkedHasNothingToHandOut(): void
    {
        self::assertNull($this->tokens()->of('other'));
    }

    public function testALinkWithoutAStoredGrantHasNothingToHandOut(): void
    {
        self::assertNull($this->tokens()->of('acme'));
    }

    public function testNothingIsHandedOutWhenNobodyIsSignedIn(): void
    {
        $this->auth->logout();
        $this->store->put($this->token());

        self::assertNull($this->tokens()->of('acme'));
    }

    public function testATokenIsOnlyEverHandedToTheAccountItBelongsTo(): void
    {
        $this->store->put($this->token(expiresAt: time() + 3600));

        $somebodyElse = $this->source->add(new Account('43'));

        self::assertNull($this->tokens()->of('acme', $somebodyElse, 'database'));
    }

    // -------------------------------------------- Withdrawn, as opposed to broken

    public function testAWithdrawnConsentIsReportedAsNothingAndLeavesNothingBehind(): void
    {
        $this->store->put($this->token(expiresAt: time() - 1));
        $this->http->on('POST', self::TOKEN, ['error' => 'invalid_grant'], 400);

        self::assertNull($this->tokens()->of('acme'));
        self::assertNull($this->store->find(self::ISSUER, 'user-1'), 'a stale copy would fail this way forever');
    }

    public function testAnOutageIsNotAWithdrawnConsent(): void
    {
        $this->store->put($this->token(expiresAt: time() - 1));
        $this->http->on('POST', self::TOKEN, ['error' => 'temporarily_unavailable'], 503);

        try {
            $this->tokens()->of('acme');
            self::fail('An unreachable provider must not read as a permission nobody granted.');
        } catch (OAuthException $e) {
            self::assertSame('refresh_failed', $e->reason);
        }

        self::assertNotNull($this->store->find(self::ISSUER, 'user-1'), 'an outage must not discard a grant');
    }

    // --------------------------------------------------------------- Remembering

    public function testWhatACallbackCarriedIsKept(): void
    {
        $this->tokens()->remember($this->callbackWith($this->token()));

        self::assertSame('at-1', $this->store->find(self::ISSUER, 'user-1')?->accessToken);
    }

    public function testACallbackThatCarriedNothingStoresNothing(): void
    {
        $this->tokens()->remember($this->callbackWith(null));

        self::assertSame([], $this->store->tokens);
    }

    // ------------------------------------------------------------------ Giving up

    public function testForgettingTellsTheProviderBeforeDeleting(): void
    {
        $this->http->on('POST', self::REVOKE, '');
        $this->store->put($this->token());

        $this->tokens()->forget('acme');

        self::assertSame(2, $this->http->calls('POST', self::REVOKE), 'both credentials are given back');
        self::assertNull($this->store->find(self::ISSUER, 'user-1'));
    }

    public function testForgettingWhatIsNotThereIsNotAnError(): void
    {
        $this->tokens()->forget('acme');

        self::assertSame(0, $this->http->calls('POST', self::REVOKE));
    }

    // --------------------------------------------------------------- Machinery

    private function tokens(): Tokens
    {
        $metadata = new Metadata($this->http, $this->cache);

        $flow = new Flow(
            provider: ProviderConfig::fromArray('acme', [
                'issuer'        => self::ISSUER,
                'client_id'     => 'client-abc',
                'client_secret' => 'shhh',
            ], 'https://app.example.test'),
            http: $this->http,
            transactions: new ArrayTransactions(),
            metadata: $metadata,
            idToken: new IdToken($metadata),
            userInfo: new UserInfo($this->http),
            offlineAccess: true,
        );

        return new Tokens(
            store: $this->store,
            providers: new OAuth(
                providers: ['acme' => ['issuer' => self::ISSUER, 'client_id' => 'client-abc']],
                factory: static fn(ProviderConfig $provider): Flow => $flow,
                publicUrl: 'https://app.example.test',
            ),
            accounts: new Accounts($this->links, $this->auth),
            auth: $this->auth,
        );
    }

    private function token(?int $expiresAt = null): ProviderToken
    {
        return new ProviderToken('acme', self::ISSUER, 'user-1', 'at-1', 'rt-1', ['openid'], $expiresAt);
    }

    private function callbackWith(?ProviderToken $token): Callback
    {
        return new Callback($this->external(), Callback::LOGIN, null, '/', $token);
    }

    private function external(): ExternalIdentity
    {
        return new ExternalIdentity('acme', self::ISSUER, 'user-1', ['iss' => self::ISSUER, 'sub' => 'user-1']);
    }
}
