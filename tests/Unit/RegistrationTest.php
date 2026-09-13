<?php

declare(strict_types=1);

namespace Tests\Unit;

use NixPHP\Auth\Auth;
use NixPHP\OAuth\Client\Account\{Accounts, PdoAccountLinks};
use NixPHP\OAuth\Client\Core\Callback;
use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Identity\ExternalIdentity;
use NixPHP\OAuth\Client\Migrations\OAuthIdentitiesMigration;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\{Account, AccountSource};

/**
 * Creating an account for a first external login, against a real database.
 *
 * Atomicity cannot be shown with an in-memory double: the question is what the
 * database is left holding when the second half fails.
 */
final class RegistrationTest extends TestCase
{
    private const string ISSUER = 'https://id.example.test';

    private PDO $connection;
    private PdoAccountLinks $links;
    private AccountSource $source;
    private Auth $auth;

    protected function setUp(): void
    {
        $this->connection = new PDO('sqlite::memory:');
        $this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->connection->exec('CREATE TABLE users (id VARCHAR(190) PRIMARY KEY)');

        (new OAuthIdentitiesMigration())->up($this->connection);

        $this->links  = new PdoAccountLinks($this->connection);
        $this->source = new AccountSource();
        $this->auth   = (new Auth())->addProvider('database', $this->source);
    }

    public function testAFirstLoginCreatesAnAccountAndLinksIt(): void
    {
        $user = $this->accounts()->complete($this->loginCallback());

        self::assertSame('new-1', $user->getIdentifier());
        self::assertSame(1, $this->countUsers());
        self::assertSame('new-1', $this->links->find(self::ISSUER, 'sub-1')?->userId);
        self::assertTrue($this->auth->check());
    }

    public function testAFailedLinkTakesTheNewAccountWithIt(): void
    {
        $this->source->add(new Account('7'));

        // The race as it actually happens: nobody held this identity when we
        // looked, and somebody did by the time we wrote.
        $accounts = $this->accounts(create: function (): Account {
            $this->connection->exec("INSERT INTO users (id) VALUES ('new-1')");
            $this->links->link($this->external(), 'database', '7');

            return $this->source->add(new Account('new-1'));
        });

        try {
            $accounts->complete($this->loginCallback());
            self::fail('Expected the registration to be refused.');
        } catch (OAuthException $e) {
            self::assertSame('already_linked', $e->reason);
        }

        // Otherwise every retry leaves another orphan beside the last one.
        self::assertSame(0, $this->countUsers(), 'the half-made account was rolled back');
        self::assertFalse($this->auth->check());
    }

    public function testANewAccountIsReadBackThroughItsOwnSource(): void
    {
        // The factory hands over one object; the source is what decides who may
        // sign in, and what signs in has to be what the next request will load.
        $accounts = $this->accounts(create: function (): Account {
            $this->connection->exec("INSERT INTO users (id) VALUES ('new-1')");

            return new Account('new-1');
        }, register: false);

        $this->assertReason('registration_refused', fn() => $accounts->complete($this->loginCallback()));

        self::assertFalse($this->auth->check(), 'an account the source will not answer for is not signed in');
    }

    public function testADatabaseFaultIsNotReportedAsAnExistingLink(): void
    {
        $this->connection->exec('DROP TABLE oauth_identities');

        // "already linked" reads like ordinary use. A broken installation must not
        // be able to hide behind it.
        $this->expectException(PDOException::class);

        $this->accounts()->complete($this->loginCallback());
    }

    // --------------------------------------------------------------- Machinery

    private function accounts(?callable $create = null, bool $register = true): Accounts
    {
        $create ??= function () use ($register): Account {
            $this->connection->exec("INSERT INTO users (id) VALUES ('new-1')");

            return $register ? $this->source->add(new Account('new-1')) : new Account('new-1');
        };

        return new Accounts(
            links: $this->links,
            auth: $this->auth,
            autoRegister: true,
            create: \Closure::fromCallable($create),
        );
    }

    private function countUsers(): int
    {
        return (int) $this->connection->query('SELECT COUNT(*) FROM users')?->fetchColumn();
    }

    private function external(): ExternalIdentity
    {
        return new ExternalIdentity(provider: 'acme', issuer: self::ISSUER, subject: 'sub-1');
    }

    private function loginCallback(): Callback
    {
        return new Callback($this->external(), Callback::LOGIN, null, '/dashboard');
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
