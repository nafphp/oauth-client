<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use NixPHP\OAuth\Client\Exception\ConfigurationException;
use NixPHP\OAuth\Client\Migrations\OAuthProviderTokensMigration;
use NixPHP\OAuth\Client\Token\Cipher;
use NixPHP\OAuth\Client\Token\PdoTokens;
use NixPHP\OAuth\Client\Token\ProviderToken;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The shipped token store, against a real database, with the shipped schema.
 *
 * The point of every test here is the same one: a copy of this table is not a
 * copy of anybody's permissions.
 */
final class PdoTokensTest extends TestCase
{
    private const string ISSUER = 'https://id.example.test';

    private PDO $connection;
    private string $key;
    private PdoTokens $tokens;

    protected function setUp(): void
    {
        $this->connection = new PDO('sqlite::memory:');
        $this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        (new OAuthProviderTokensMigration())->up($this->connection);

        $this->key    = Cipher::generateKey();
        $this->tokens = new PdoTokens($this->connection, Cipher::fromKey($this->key));
    }

    public function testTheMigrationCreatesSomethingUsable(): void
    {
        $this->tokens->put($this->token());

        $found = $this->tokens->find(self::ISSUER, 'user-42');

        self::assertNotNull($found);
        self::assertSame('acme', $found->provider);
        self::assertSame('at-1', $found->accessToken);
        self::assertSame('rt-1', $found->refreshToken);
        self::assertSame(['openid', 'calendar'], $found->scope);
        self::assertSame(1900000000, $found->expiresAt);
    }

    public function testNothingUsableIsWrittenInTheClear(): void
    {
        $this->tokens->put($this->token());

        $row = $this->row();

        self::assertStringNotContainsString('at-1', $row['access_token']);
        self::assertStringNotContainsString('rt-1', (string) $row['refresh_token']);

        // The parts that are not credentials stay readable, or the table could
        // not be reasoned about at all.
        self::assertSame('openid calendar', $row['scope']);
        self::assertSame(self::ISSUER, $row['issuer']);
    }

    public function testACiphertextIsNoUseInAnotherRow(): void
    {
        $this->tokens->put($this->token());
        $this->tokens->put($this->token(subject: 'somebody-else', accessToken: 'at-2'));

        // Lifting one person's access token onto another person's row. The bytes
        // are valid; where they now sit is not.
        $stolen = $this->row('user-42')['access_token'];
        $this->connection
            ->prepare('UPDATE oauth_provider_tokens SET access_token = :value WHERE subject = :subject')
            ->execute(['value' => $stolen, 'subject' => 'somebody-else']);

        $this->expectException(ConfigurationException::class);
        $this->tokens->find(self::ISSUER, 'somebody-else');
    }

    public function testAnotherKeyDoesNotOpenIt(): void
    {
        $this->tokens->put($this->token());

        $other = new PdoTokens($this->connection, Cipher::fromKey(Cipher::generateKey()));

        $this->expectException(ConfigurationException::class);
        $other->find(self::ISSUER, 'user-42');
    }

    public function testWritingAgainReplacesTheGrant(): void
    {
        $this->tokens->put($this->token());
        $this->tokens->put($this->token(accessToken: 'at-2', scope: ['openid']));

        $found = $this->tokens->find(self::ISSUER, 'user-42');

        self::assertNotNull($found);
        self::assertSame('at-2', $found->accessToken);
        self::assertSame(['openid'], $found->scope);
        self::assertSame(1, (int) $this->connection->query('SELECT COUNT(*) FROM oauth_provider_tokens')?->fetchColumn());
    }

    public function testWritingTheSameValuesBackIsStillAWrite(): void
    {
        // MySQL's rowCount() counts rows it changed rather than rows it matched,
        // so an update that changes nothing reads as a miss. Nothing here may
        // depend on that answer.
        $this->tokens->put($this->token());
        $this->tokens->put($this->token());

        self::assertNotNull($this->tokens->find(self::ISSUER, 'user-42'));
        self::assertSame(1, (int) $this->connection->query('SELECT COUNT(*) FROM oauth_provider_tokens')?->fetchColumn());
    }

    public function testAGrantWithoutARefreshTokenIsStoredAsSuch(): void
    {
        $this->tokens->put($this->token(refreshToken: null));

        $found = $this->tokens->find(self::ISSUER, 'user-42');

        self::assertNotNull($found);
        self::assertNull($found->refreshToken);
    }

    public function testForgettingRemovesIt(): void
    {
        $this->tokens->put($this->token());
        $this->tokens->forget(self::ISSUER, 'user-42');

        self::assertNull($this->tokens->find(self::ISSUER, 'user-42'));
    }

    public function testAnUnknownIdentityHasNothing(): void
    {
        self::assertNull($this->tokens->find(self::ISSUER, 'nobody'));
    }

    public function testTheTableNameHasToBeOne(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new PdoTokens($this->connection, Cipher::fromKey($this->key), 'tokens; DROP TABLE users');
    }

    // ------------------------------------------------------------------- The key

    public function testAMissingKeyIsRefusedBeforeAnythingIsWritten(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/oauth:tokens:key/');

        Cipher::fromKey(null);
    }

    public function testAKeyOfTheWrongSizeIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);

        Cipher::fromKey(base64_encode('too short'));
    }

    public function testSomethingThatIsNotBase64IsRefused(): void
    {
        $this->expectException(ConfigurationException::class);

        Cipher::fromKey('not base64 at all!!');
    }

    public function testTheSameTextEncryptsDifferentlyEveryTime(): void
    {
        $cipher = Cipher::fromKey($this->key);

        // A repeated nonce would leak that two people hold the same token, and
        // with this construction it would leak considerably more than that.
        self::assertNotSame($cipher->encrypt('same', 'ctx'), $cipher->encrypt('same', 'ctx'));
        self::assertSame('same', $cipher->decrypt($cipher->encrypt('same', 'ctx'), 'ctx'));
    }

    public function testAValueFromAnUnknownFormatIsRefusedRatherThanGuessed(): void
    {
        $this->expectException(ConfigurationException::class);

        Cipher::fromKey($this->key)->decrypt('x9:' . base64_encode(str_repeat('a', 40)), 'ctx');
    }

    // --------------------------------------------------------------- Machinery

    /** @param list<string> $scope */
    private function token(
        string $subject = 'user-42',
        string $accessToken = 'at-1',
        ?string $refreshToken = 'rt-1',
        array $scope = ['openid', 'calendar'],
    ): ProviderToken {
        return new ProviderToken('acme', self::ISSUER, $subject, $accessToken, $refreshToken, $scope, 1900000000);
    }

    /** @return array<string, mixed> */
    private function row(string $subject = 'user-42'): array
    {
        $statement = $this->connection->prepare('SELECT * FROM oauth_provider_tokens WHERE subject = :subject');
        $statement->execute(['subject' => $subject]);

        /** @var array<string, mixed> $row */
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return $row;
    }
}
