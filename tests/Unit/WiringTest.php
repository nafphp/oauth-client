<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Auth\Auth;
use Naf\CLI\Support\CommandRegistry;
use Naf\Core\Config;
use Naf\Database\Support\MigrationRegistry;
use Naf\OAuth\Client\Account\AccountLinkStoreInterface;
use Naf\OAuth\Client\Account\Accounts;
use Naf\OAuth\Client\Commands\DiscoverCommand;
use Naf\OAuth\Client\Core\IdToken;
use Naf\OAuth\Client\Core\Metadata;
use Naf\OAuth\Client\Core\OAuth;
use Naf\OAuth\Client\Core\TransactionStoreInterface;
use Naf\OAuth\Client\Exception\ConfigurationException;
use Naf\OAuth\Client\Token\Cipher;
use Naf\OAuth\Client\Token\Tokens;
use Naf\OAuth\Client\Token\TokenStoreInterface;
use PDO;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Tests\Fixtures\AccountSource;
use Tests\Fixtures\ArrayTransactions;
use Tests\Fixtures\FakeHttp;
use Tests\Fixtures\MemoryLinks;

use function Naf\app;
use function Naf\OAuth\Client\oauth;

/** What bootstrap.php registers, and what it leaves to the application. */
final class WiringTest extends TestCase
{
    private const array SERVICES = [
        OAuth::class, Metadata::class, IdToken::class, TransactionStoreInterface::class,
        ClientInterface::class, Accounts::class, AccountLinkStoreInterface::class,
        Config::class, PDO::class, Cipher::class, TokenStoreInterface::class, Tokens::class,
    ];

    protected function setUp(): void
    {
        if (!defined('BASE_PATH')) {
            define('BASE_PATH', dirname(__DIR__) . '/Fixtures');
        }

        $this->reset();
    }

    protected function tearDown(): void
    {
        $this->reset();
    }

    // ------------------------------------------------------------- Providers

    public function testAConfiguredProviderIsResolvedThroughTheHelper(): void
    {
        $this->configure(['providers' => ['acme' => [
            'issuer' => 'https://id.example.test', 'client_id' => 'abc',
        ]]]);
        $this->boot();

        $flow = oauth('acme');

        self::assertSame('acme', $flow->key());
        self::assertSame('Acme', $flow->label(), 'an unknown provider falls back to its own key');
        self::assertSame($flow, oauth('acme'), 'resolved once');
    }

    public function testTheOlderConfigurationStillWorks(): void
    {
        // oauth:providers is the previous spelling. An application that used it
        // keeps working, and hears about its own keys when something is wrong.
        $this->configure(['providers' => ['acme' => ['client_id' => 'abc']]]);
        $this->boot();

        self::assertSame(['acme'], app()->container()->get(OAuth::class)->names());
        $this->assertConfigurationError('oauth:providers:acme:issuer', static fn() => oauth('acme'));
    }

    public function testAnUnconfiguredProviderSaysWhatIsConfigured(): void
    {
        $this->configure(['providers' => ['acme' => ['issuer' => 'https://id.example.test', 'client_id' => 'abc']]]);
        $this->boot();

        $this->assertConfigurationError('acme', static fn() => oauth('nope'));
    }

    public function testWithoutAPublicUrlNothingStarts(): void
    {
        $this->configure(['providers' => ['acme' => ['issuer' => 'https://id.example.test', 'client_id' => 'abc']]], publicUrl: null);
        $this->boot();

        $this->assertConfigurationError('public_url', static fn() => oauth('acme'));
    }

    public function testNoProviderIsBuiltUntilSomebodyUsesOne(): void
    {
        $this->configure(['providers' => ['broken' => []]]);
        $this->boot();

        // A provider missing its client_id is a setup error, but only for whoever
        // reaches that provider — booting five of them builds none.
        self::assertTrue(app()->container()->get(OAuth::class)->has('broken'));
        $this->assertConfigurationError('client_id', static fn() => oauth('broken'));
    }

    // -------------------------------------------------------------- Accounts

    public function testTheAccountResolverUsesTheSoleAuthSource(): void
    {
        app()->container()->set(AccountLinkStoreInterface::class, new MemoryLinks());
        app()->container()->set(AccountSource::class, new AccountSource());
        $this->configure([], auth: ['session' => false, 'providers' => ['database' => AccountSource::class]]);
        $this->boot();

        self::assertInstanceOf(Accounts::class, app()->container()->get(Accounts::class));
    }

    public function testACallableIsRequiredForAutomaticRegistration(): void
    {
        app()->container()->set(AccountLinkStoreInterface::class, new MemoryLinks());
        $this->configure(['accounts' => ['auto_register' => true, 'create' => 'not a function']]);
        $this->boot();

        $this->assertConfigurationError(
            'oauth:accounts:create',
            static fn() => app()->container()->get(Accounts::class),
        );
    }

    public function testTheLinkStoreNeedsAConnectionAndSaysSo(): void
    {
        $this->configure([]);
        $this->boot();

        $this->assertConfigurationError(
            'PDO',
            static fn() => app()->container()->get(AccountLinkStoreInterface::class),
        );
    }

    public function testTheLinkStoreUsesTheApplicationsConnection(): void
    {
        app()->container()->set(PDO::class, new PDO('sqlite::memory:'));
        $this->configure([]);
        $this->boot();

        self::assertInstanceOf(AccountLinkStoreInterface::class, app()->container()->get(AccountLinkStoreInterface::class));
    }

    // --------------------------------------------------------- Provider tokens

    public function testNothingIsKeptUnlessAnApplicationAsksForIt(): void
    {
        app()->container()->set(PDO::class, new PDO('sqlite::memory:'));
        $this->configure([]);
        $this->boot();

        // Holding a refresh token is holding a standing permission to act as
        // somebody. It is not something to end up with by installing a plugin.
        $this->assertConfigurationError(
            'oauth:tokens:store',
            static fn() => app()->container()->get(TokenStoreInterface::class),
        );
    }

    public function testKeepingThemNeedsSomethingToEncryptThemWith(): void
    {
        app()->container()->set(PDO::class, new PDO('sqlite::memory:'));
        $this->configure(['tokens' => ['store' => true]]);
        $this->boot();

        $this->assertConfigurationError(
            'oauth:tokens:key',
            static fn() => app()->container()->get(TokenStoreInterface::class),
        );
    }

    public function testTheTokenStoreUsesTheApplicationsConnection(): void
    {
        app()->container()->set(PDO::class, new PDO('sqlite::memory:'));
        $this->configure(['tokens' => ['store' => true, 'key' => Cipher::generateKey()]]);
        $this->boot();

        self::assertInstanceOf(TokenStoreInterface::class, app()->container()->get(TokenStoreInterface::class));
        self::assertInstanceOf(Tokens::class, app()->container()->get(Tokens::class));
    }

    public function testALoginOnlyAsksForOfflineAccessWhereSomethingWillKeepIt(): void
    {
        app()->container()->set(ClientInterface::class, $this->provider());
        app()->container()->set(TransactionStoreInterface::class, new ArrayTransactions());

        $this->configure(['providers' => ['acme' => [
            'issuer' => 'https://id.example.test', 'client_id' => 'abc',
        ]]]);
        $this->boot();

        self::assertStringNotContainsString('offline_access', oauth('acme')->authorizationUrl());

        $this->reset();
        app()->container()->set(ClientInterface::class, $this->provider());
        app()->container()->set(TransactionStoreInterface::class, new ArrayTransactions());

        $this->configure([
            'providers' => ['acme' => ['issuer' => 'https://id.example.test', 'client_id' => 'abc']],
            'tokens'    => ['store' => true, 'key' => Cipher::generateKey()],
        ]);
        $this->boot();

        self::assertStringContainsString('offline_access', oauth('acme')->authorizationUrl());
    }

    // ------------------------------------------------------- Own bindings win

    public function testApplicationBindingsTakePrecedence(): void
    {
        $http  = new FakeHttp();
        $store = new ArrayTransactions();

        app()->container()->set(ClientInterface::class, $http);
        app()->container()->set(TransactionStoreInterface::class, $store);

        $this->configure([]);
        $this->boot();

        self::assertSame($http, app()->container()->get(ClientInterface::class));
        self::assertSame($store, app()->container()->get(TransactionStoreInterface::class));
    }

    public function testBootingTwiceKeepsWhatIsAlreadyThere(): void
    {
        $this->configure(['providers' => ['acme' => ['issuer' => 'https://id.example.test', 'client_id' => 'abc']]]);
        $this->boot();

        $registry = app()->container()->get(OAuth::class);

        $this->boot();

        self::assertSame($registry, app()->container()->get(OAuth::class));
    }

    // ------------------------------------------------- Optional integrations

    public function testTheMigrationAndTheCommandAreOfferedWhenTheirPluginsAreThere(): void
    {
        $this->configure([]);
        $this->boot();

        self::assertTrue(app()->hasPlugin('naf/database'), 'precondition for this test');
        self::assertContains(
            realpath(dirname(__DIR__, 2) . '/src/Migrations'),
            array_map(realpath(...), MigrationRegistry::getPaths()),
        );

        self::assertTrue(app()->hasPlugin('naf/cli'), 'precondition for this test');
        self::assertSame(
            DiscoverCommand::class,
            app()->container()->get(CommandRegistry::class)->get(DiscoverCommand::NAME),
        );
    }

    // --------------------------------------------------------------- Machinery

    /**
     * @param array<string, mixed> $oauth
     * @param array<string, mixed>|null $auth
     */
    private function configure(array $oauth, ?string $publicUrl = 'https://app.example.test', ?array $auth = null): void
    {
        app()->container()->set(Config::class, new Config([
            'public_url' => $publicUrl,
            'oauth'      => $oauth,
            'auth'       => $auth ?? ['session' => false, 'providers' => []],
        ]));
    }

    private function boot(): void
    {
        // Accounts asks the container for Auth, which the auth plugin registers in
        // its own bootstrap. Both guard their factories, so re-running is a no-op.
        require dirname(__DIR__, 2) . '/vendor/naf/auth/bootstrap.php';
        require dirname(__DIR__, 2) . '/bootstrap.php';
    }

    private function reset(): void
    {
        $container = app()->container();

        foreach (self::SERVICES as $service) {
            $container->reset($service);
        }

        $container->reset(Auth::class);
    }

    private function provider(): FakeHttp
    {
        $http = new FakeHttp();
        $http->on('GET', 'https://id.example.test/.well-known/openid-configuration', [
            'issuer'                 => 'https://id.example.test',
            'authorization_endpoint' => 'https://id.example.test/authorize',
            'token_endpoint'         => 'https://id.example.test/token',
        ]);

        return $http;
    }

    private function assertConfigurationError(string $needle, callable $run): void
    {
        try {
            $run();
            self::fail('Expected a ConfigurationException mentioning "' . $needle . '".');
        } catch (ConfigurationException $e) {
            self::assertStringContainsString($needle, $e->getMessage());
        } catch (ContainerExceptionInterface $e) {
            // The container wraps factory failures; the message is carried through.
            self::assertStringContainsString($needle, $e->getMessage());
        }
    }
}
