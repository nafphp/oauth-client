<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Auth\Auth;
use Naf\OAuth\Client\Account\Accounts;
use Naf\OAuth\Client\Core\Callback;
use Naf\OAuth\Client\Exception\ConfigurationException;
use Naf\OAuth\Client\Exception\OAuthException;
use Naf\OAuth\Client\Identity\ExternalIdentity;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\{Account, AccountSource, MemoryLinks};

/** Which local account a verified external identity belongs to — and which it never does. */
final class AccountsTest extends TestCase
{
    private const string ISSUER = 'https://id.example.test';

    private MemoryLinks $links;
    private AccountSource $source;
    private Auth $auth;

    protected function setUp(): void
    {
        $this->links  = new MemoryLinks();
        $this->source = new AccountSource();
        $this->auth   = (new Auth())->addProvider('database', $this->source);
    }

    // ------------------------------------------------------------- Signing in

    public function testALinkedIdentitySignsInItsAccount(): void
    {
        $account = $this->source->add(new Account('42'));
        $this->links->link($this->external(), 'database', '42');

        $signedIn = $this->accounts()->complete($this->loginCallback());

        self::assertSame($account, $signedIn);
        self::assertSame($account, $this->auth->user());
        self::assertSame('database', $this->auth->providerName());
    }

    public function testASuspendedAccountCannotSignInAndKeepsItsLink(): void
    {
        $this->source->add(new Account('42', active: false));
        $this->links->link($this->external(), 'database', '42');

        $this->assertReason('account_unavailable', fn() => $this->accounts()->complete($this->loginCallback()));

        self::assertFalse($this->auth->check());
        self::assertNotNull($this->links->find(self::ISSUER, 'sub-1'), 'an outage must not unlink anybody');
    }

    public function testAnUnlinkedIdentityIsRefusedByDefault(): void
    {
        $this->source->add(new Account('42'));

        $this->assertReason('not_linked', fn() => $this->accounts()->complete($this->loginCallback()));

        self::assertFalse($this->auth->check());
    }

    public function testAMatchingVerifiedEmailIsNotALink(): void
    {
        // The account exists, the address matches, the provider says it is verified.
        // It is still not proof that the person at the provider owns this account.
        $this->source->add(new Account('42'));

        $external = new ExternalIdentity(
            provider: 'acme',
            issuer: self::ISSUER,
            subject: 'sub-1',
            email: 'alice@example.test',
            emailVerified: true,
        );

        $this->assertReason('not_linked', fn() => $this->accounts()->complete($this->loginCallback($external)));
    }

    public function testAutoRegistrationCreatesAndLinksInThatOrder(): void
    {
        $accounts = $this->accounts(autoRegister: true, create: function (ExternalIdentity $external): Account {
            self::assertSame('alice@example.test', $external->email);

            return $this->source->add(new Account('99'));
        });

        $signedIn = $accounts->complete($this->loginCallback());

        self::assertSame('99', $signedIn->getIdentifier());
        self::assertSame('99', $this->links->find(self::ISSUER, 'sub-1')?->userId);
        self::assertSame('99', $this->auth->id());
    }

    public function testARefusedRegistrationSignsNobodyIn(): void
    {
        $accounts = $this->accounts(autoRegister: true, create: static fn(): ?Account => null);

        $this->assertReason('registration_refused', fn() => $accounts->complete($this->loginCallback()));

        self::assertFalse($this->auth->check());
        self::assertSame([], $this->links->links);
    }

    public function testAutoRegistrationWithoutAFactoryIsASetupError(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/oauth:accounts:create/');

        $this->accounts(autoRegister: true)->complete($this->loginCallback());
    }

    // -------------------------------------------------- Choosing the source

    public function testTheOnlyAccountSourceNeedsNoNaming(): void
    {
        $accounts = $this->accounts(autoRegister: true, create: fn(): Account => $this->source->add(new Account('7')));

        $accounts->complete($this->loginCallback());

        self::assertSame('database', $this->links->find(self::ISSUER, 'sub-1')?->userProvider);
    }

    public function testSeveralAccountSourcesAskWhichOne(): void
    {
        $this->auth->addProvider('ldap', new AccountSource());

        $accounts = new Accounts(
            links: $this->links,
            auth: $this->auth,
            autoRegister: true,
            create: fn(): Account => $this->source->add(new Account('7')),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/oauth:accounts:provider/');

        $accounts->complete($this->loginCallback());
    }

    // ---------------------------------------------------------------- Linking

    public function testLinkingAttachesTheProviderToWhoStartedIt(): void
    {
        $account = $this->source->add(new Account('42'));
        $this->auth->setIdentity($account, 'database');

        $stillSignedIn = $this->accounts()->complete($this->linkCallback('database', '42'));

        self::assertSame($account, $stillSignedIn);
        self::assertSame('42', $this->links->find(self::ISSUER, 'sub-1')?->userId);
    }

    public function testLinkingTwiceChangesNothing(): void
    {
        $account = $this->source->add(new Account('42'));
        $this->auth->setIdentity($account, 'database');
        $this->links->link($this->external(), 'database', '42');

        $this->accounts()->complete($this->linkCallback('database', '42'));

        self::assertCount(1, $this->links->links);
    }

    public function testAProviderAccountCannotBeStolenFromSomebodyElse(): void
    {
        $this->source->add(new Account('7'));
        $thief = $this->source->add(new Account('42'));
        $this->auth->setIdentity($thief, 'database');
        $this->links->link($this->external(), 'database', '7');

        $this->assertReason('already_linked', fn() => $this->accounts()->complete($this->linkCallback('database', '42')));

        self::assertSame('7', $this->links->find(self::ISSUER, 'sub-1')?->userId);
    }

    public function testALinkCannotBeFinishedByAnybodyElse(): void
    {
        $other = $this->source->add(new Account('99'));
        $this->source->add(new Account('42'));
        $this->auth->setIdentity($other, 'database');

        // Started by 42, finished while 99 is signed in.
        $this->assertReason('initiator_mismatch', fn() => $this->accounts()->complete($this->linkCallback('database', '42')));

        self::assertSame([], $this->links->links);
    }

    public function testALinkCannotBeFinishedByAGuest(): void
    {
        $this->source->add(new Account('42'));

        $this->assertReason('initiator_mismatch', fn() => $this->accounts()->complete($this->linkCallback('database', '42')));
    }

    public function testALinkCallbackWithoutAnInitiatorIsRefused(): void
    {
        $account = $this->source->add(new Account('42'));
        $this->auth->setIdentity($account, 'database');

        $callback = new Callback($this->external(), Callback::LINK, null, '/');

        $this->assertReason('no_initiator', fn() => $this->accounts()->complete($callback));
    }

    public function testAnAccountListsWhatItCanSignInWith(): void
    {
        $account = $this->source->add(new Account('42'));
        $this->links->link($this->external(), 'database', '42');
        $this->links->link($this->external('https://other.test', 'sub-9', 'other'), 'database', '42');
        $this->links->link($this->external('https://third.test', 'sub-3'), 'database', '99');

        self::assertCount(2, $this->accounts()->of($account));
    }

    // --------------------------------------------------------------- Machinery

    private function accounts(bool $autoRegister = false, ?callable $create = null): Accounts
    {
        return new Accounts(
            links: $this->links,
            auth: $this->auth,
            autoRegister: $autoRegister,
            create: $create === null ? null : \Closure::fromCallable($create),
        );
    }

    private function external(string $issuer = self::ISSUER, string $subject = 'sub-1', string $provider = 'acme'): ExternalIdentity
    {
        return new ExternalIdentity(
            provider: $provider,
            issuer: $issuer,
            subject: $subject,
            email: 'alice@example.test',
            emailVerified: true,
        );
    }

    private function loginCallback(?ExternalIdentity $external = null): Callback
    {
        return new Callback($external ?? $this->external(), Callback::LOGIN, null, '/dashboard');
    }

    private function linkCallback(string $provider, string $id): Callback
    {
        return new Callback($this->external(), Callback::LINK, ['provider' => $provider, 'id' => $id], '/account');
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
