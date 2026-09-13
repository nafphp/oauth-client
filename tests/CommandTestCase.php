<?php

declare(strict_types=1);

namespace Tests;

use Naf\Auth\Auth;
use Naf\CLI\Core\{AbstractCommand, Input, Output};
use Naf\Core\Config;
use Naf\OAuth\Client\Account\{AccountLinkStoreInterface, Accounts};
use Naf\OAuth\Client\Core\{IdToken, Metadata, OAuth, TransactionStoreInterface, UserInfo};
use Naf\OAuth\Client\Migrations\{OAuthIdentitiesMigration, OAuthProviderTokensMigration};
use Naf\OAuth\Client\Token\{Cipher, Tokens, TokenStoreInterface};
use PDO;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Tests\Fixtures\FakeHttp;
use Tests\Fixtures\Signer;
use function Naf\app;

/**
 * Runs a command the way the console runs it.
 *
 * The commands here are diagnosis: they exist to be read by somebody deciding
 * whether a setup works. That makes what they print part of their behaviour, and
 * it is not behaviour any unit below them has — a command that resolves the
 * configuration from a different place than the application does is wrong in a
 * way every class it calls is individually right.
 *
 * So these tests build an application, run the command against it, and read what
 * came out. Nothing is mocked that the command would otherwise have resolved;
 * only the two things a test may not have are supplied — a provider that answers
 * without a network, and a database in memory.
 */
abstract class CommandTestCase extends TestCase
{
    /** Everything the plugin registers, cleared between tests so each boots fresh. */
    private const array SERVICES = [
        OAuth::class, Metadata::class, IdToken::class, UserInfo::class,
        TransactionStoreInterface::class, ClientInterface::class,
        Accounts::class, AccountLinkStoreInterface::class,
        Cipher::class, TokenStoreInterface::class, Tokens::class,
        Config::class, PDO::class,
    ];

    private static ?Signer $signer = null;

    protected string $cache;

    protected function setUp(): void
    {
        if (!defined('BASE_PATH')) {
            define('BASE_PATH', dirname(__DIR__) . '/tests/Fixtures');
        }

        $this->cache = sys_get_temp_dir() . '/naf-oauth-cmd-' . bin2hex(random_bytes(6));

        $this->reset();
    }

    protected function tearDown(): void
    {
        $this->reset();

        foreach (glob($this->cache . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->cache);
    }

    // ------------------------------------------------------------- Building one

    /**
     * @param array<string, mixed> $oauth What goes under "oauth".
     * @param array<string, mixed>|null $auth What goes under "auth". Null registers no login.
     */
    protected function configure(array $oauth = [], ?array $auth = null, ?string $publicUrl = 'https://app.example.test'): void
    {
        app()->container()->set(Config::class, new Config([
            'public_url' => $publicUrl,

            // Never the application's own directory: a command that warms a cache
            // would otherwise leave it in the repository.
            'oauth' => ['cache_path' => $this->cache] + $oauth,
            'auth'  => $auth ?? ['session' => false, 'providers' => []],
        ]));
    }

    /**
     * A provider that answers without a network.
     *
     * Scripted rather than mocked: the command reaches it through the very same
     * PSR-18 binding an application would, so the transport, the metadata cache
     * and the issuer check all run for real.
     */
    protected function provider(string $issuer = 'https://id.example.test'): FakeHttp
    {
        $http = new FakeHttp();

        $http->on('GET', $issuer . '/.well-known/openid-configuration', [
            'issuer'                                => $issuer,
            'authorization_endpoint'                => $issuer . '/authorize',
            'token_endpoint'                        => $issuer . '/token',
            'jwks_uri'                              => $issuer . '/jwks',
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        // Generating an RSA key is slow, and every test wants the same one.
        $http->on('GET', $issuer . '/jwks', (self::$signer ??= new Signer())->jwks());

        app()->container()->set(ClientInterface::class, $http);

        return $http;
    }

    /** A database with the tables the plugin's own migrations create. */
    protected function database(): PDO
    {
        $connection = new PDO('sqlite::memory:');
        $connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        (new OAuthIdentitiesMigration())->up($connection);
        (new OAuthProviderTokensMigration())->up($connection);

        app()->container()->set(PDO::class, $connection);

        return $connection;
    }

    protected function boot(): void
    {
        // Accounts asks the container for Auth, which the auth plugin registers in
        // its own bootstrap. Both guard their factories, so re-running is a no-op.
        require dirname(__DIR__) . '/vendor/naf/auth/bootstrap.php';
        require dirname(__DIR__) . '/bootstrap.php';
    }

    // ------------------------------------------------------------- Running one

    /**
     * @param list<string> $parameters Everything after the command name, as a shell passes it.
     */
    protected function execute(AbstractCommand $command, array $parameters = []): CommandResult
    {
        $input  = new Input($parameters, $command->getDefinition());
        $output = new Output();

        ob_start();

        try {
            $status = $command->run($input, $output);
        } finally {
            $printed = (string) ob_get_clean();
        }

        // Colour is for a terminal, not for an assertion.
        return new CommandResult($status, (string) preg_replace('/\x1b\[[0-9;]*m/', '', $printed));
    }

    protected function assertSucceeded(CommandResult $result): void
    {
        self::assertSame(0, $result->status, 'Expected a zero exit status. Printed:' . PHP_EOL . $result->output);
    }

    protected function assertFailed(CommandResult $result): void
    {
        self::assertNotSame(0, $result->status, 'Expected a non-zero exit status. Printed:' . PHP_EOL . $result->output);
    }

    private function reset(): void
    {
        $container = app()->container();

        foreach (self::SERVICES as $service) {
            $container->reset($service);
        }

        $container->reset(Auth::class);
    }
}
