<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use NixPHP\OAuth\Client\Account\PdoAccountLinks;
use NixPHP\OAuth\Client\Exception\OAuthException;
use NixPHP\OAuth\Client\Identity\ExternalIdentity;
use NixPHP\OAuth\Client\Migrations\OAuthIdentitiesMigration;
use PDO;
use PHPUnit\Framework\TestCase;

/** The shipped store, against a real database, with the shipped schema. */
final class PdoAccountLinksTest extends TestCase
{
    private PDO $connection;
    private PdoAccountLinks $links;

    protected function setUp(): void
    {
        $this->connection = new PDO('sqlite::memory:');
        $this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        (new OAuthIdentitiesMigration())->up($this->connection);

        $this->links = new PdoAccountLinks($this->connection);
    }

    public function testTheMigrationCreatesSomethingUsable(): void
    {
        $link = $this->links->link($this->external(), 'database', '42');

        self::assertSame('acme', $link->provider);
        self::assertSame('42', $link->userId);

        $found = $this->links->find('https://id.example.test', 'sub-1');

        self::assertNotNull($found);
        self::assertSame('database', $found->userProvider);
        self::assertSame('42', $found->userId);
        self::assertSame('https://id.example.test', $found->issuer);
        self::assertSame('sub-1', $found->subject);
    }

    public function testAnIdentityNobodyLinkedIsNotFound(): void
    {
        self::assertNull($this->links->find('https://id.example.test', 'sub-1'));
    }

    public function testTheDatabaseItselfRefusesASecondOwner(): void
    {
        $this->links->link($this->external(), 'database', '42');

        // Not a check the caller has to remember: two simultaneous first logins
        // cannot both create the link, whatever either of them saw a moment ago.
        try {
            $this->links->link($this->external(), 'database', '99');
            self::fail('Expected the primary key to refuse this.');
        } catch (OAuthException $e) {
            self::assertSame('already_linked', $e->reason);
        }

        self::assertSame('42', $this->links->find('https://id.example.test', 'sub-1')?->userId);
    }

    public function testTheSameSubjectAtAnotherIssuerIsSomebodyElse(): void
    {
        $this->links->link($this->external('https://a.test', 'sub-1'), 'database', '1');
        $this->links->link($this->external('https://b.test', 'sub-1'), 'database', '2');

        self::assertSame('1', $this->links->find('https://a.test', 'sub-1')?->userId);
        self::assertSame('2', $this->links->find('https://b.test', 'sub-1')?->userId);
    }

    public function testTheSameIdentifierInAnotherAccountSourceIsSomebodyElse(): void
    {
        $this->links->link($this->external('https://a.test', 'sub-1'), 'database', '42');
        $this->links->link($this->external('https://b.test', 'sub-2'), 'ldap', '42');

        self::assertCount(1, $this->links->forAccount('database', '42'));
        self::assertCount(1, $this->links->forAccount('ldap', '42'));
        self::assertSame('https://b.test', $this->links->forAccount('ldap', '42')[0]->issuer);
    }

    public function testAnAccountListsEveryProviderItCanUse(): void
    {
        $this->links->link($this->external('https://a.test', 'sub-1', 'google'), 'database', '42');
        $this->links->link($this->external('https://b.test', 'sub-2', 'microsoft'), 'database', '42');
        $this->links->link($this->external('https://c.test', 'sub-3', 'google'), 'database', '99');

        $providers = array_map(
            static fn($link): string => $link->provider,
            $this->links->forAccount('database', '42'),
        );

        sort($providers);

        self::assertSame(['google', 'microsoft'], $providers);
    }

    public function testUnlinkingFreesTheIdentityAgain(): void
    {
        $this->links->link($this->external(), 'database', '42');
        $this->links->unlink('https://id.example.test', 'sub-1');

        self::assertNull($this->links->find('https://id.example.test', 'sub-1'));

        $this->links->link($this->external(), 'database', '99');

        self::assertSame('99', $this->links->find('https://id.example.test', 'sub-1')?->userId);
    }

    public function testUnlinkingSomethingThatIsNotThereIsHarmless(): void
    {
        $this->links->unlink('https://id.example.test', 'sub-1');

        $this->addToAssertionCount(1);
    }

    public function testATableNameHasToBeATableName(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new PdoAccountLinks($this->connection, 'oauth_identities; DROP TABLE users');
    }

    public function testTheMigrationIsReversibleAndRepeatable(): void
    {
        $migration = new OAuthIdentitiesMigration();

        $migration->up($this->connection);   // again: CREATE TABLE IF NOT EXISTS
        $this->links->link($this->external(), 'database', '42');

        $migration->down($this->connection);

        self::assertSame(
            [],
            $this->connection->query("SELECT name FROM sqlite_master WHERE name = 'oauth_identities'")?->fetchAll() ?: [],
        );
    }

    private function external(
        string $issuer = 'https://id.example.test',
        string $subject = 'sub-1',
        string $provider = 'acme',
    ): ExternalIdentity {
        return new ExternalIdentity(provider: $provider, issuer: $issuer, subject: $subject);
    }
}
