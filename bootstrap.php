<?php

declare(strict_types=1);

use Naf\Auth\Auth;
use Naf\CLI\Support\CommandRegistry;
use Naf\Client\Core\Client;
use Naf\Database\Core\Database;
use Naf\Database\Support\MigrationRegistry;
use Naf\OAuth\Client\Account\AccountLinkStoreInterface;
use Naf\OAuth\Client\Account\Accounts;
use Naf\OAuth\Client\Account\PdoAccountLinks;
use Naf\OAuth\Client\Commands\DiscoverCommand;
use Naf\OAuth\Client\Commands\DoctorCommand;
use Naf\OAuth\Client\Core\Flow;
use Naf\OAuth\Client\Core\IdToken;
use Naf\OAuth\Client\Core\Metadata;
use Naf\OAuth\Client\Core\OAuth;
use Naf\OAuth\Client\Core\SessionTransactions;
use Naf\OAuth\Client\Core\TransactionStoreInterface;
use Naf\OAuth\Client\Core\UserInfo;
use Naf\OAuth\Client\Exception\ConfigurationException;
use Naf\OAuth\Client\Provider\ProviderConfig;
use Naf\OAuth\Client\Token\Cipher;
use Naf\OAuth\Client\Token\PdoTokens;
use Naf\OAuth\Client\Token\Tokens;
use Naf\OAuth\Client\Token\TokenStoreInterface;
use Naf\Session\Core\Session;
use Psr\Http\Client\ClientInterface;

use function Naf\app;
use function Naf\config;

$container = app()->container();

/**
 * The adapters need a PDO connection, and naf/database registers a Database.
 * Bridging that here means an ordinary installation resolves on its own instead
 * of asking for a container binding nobody would think to write.
 */
if (!$container->has(PDO::class) && app()->hasPlugin('naf/database')) {
    $container->set(PDO::class, static function () use ($container): PDO {
        $connection = $container->get(Database::class)?->getConnection();

        if (!$connection instanceof PDO) {
            throw new ConfigurationException(
                'naf/database is installed but has no connection configured, so there is no '
                . PDO::class . ' to work with. Configure "database", or bind your own connection.',
            );
        }

        return $connection;
    });
}

// Factories run on first use. Application bindings take precedence throughout.
if (!$container->has(ClientInterface::class)) {
    $container->set(ClientInterface::class, static function () use ($container): ClientInterface {
        if (!class_exists(Client::class) || !$container->has(Client::class)) {
            throw new ConfigurationException(
                'naf/oauth-client needs a PSR-18 client. Run "composer require naf/client", '
                . 'or bind your own to ' . ClientInterface::class . '.',
            );
        }

        // Two things this copy of the shared client must not do.
        //
        // Retry: an authorization code is spent the moment it reaches the
        // provider, whether or not the answer reaches us, so retrying one turns a
        // working login into "invalid_grant".
        //
        // Follow a redirect: the token request carries client credentials to an
        // address the configuration vouched for. A 307 elsewhere would carry them
        // somewhere nobody vouched for.
        return $container->get(Client::class)->withOptions(['retries' => 0, 'max_redirects' => 0]);
    });
}

if (!$container->has(Metadata::class)) {
    $container->set(Metadata::class, static fn(): Metadata => new Metadata(
        http: $container->get(ClientInterface::class),
        path: config('oauth:cache_path') ?? app()->getBasePath() . '/storage/oauth',
    ));
}

if (!$container->has(IdToken::class)) {
    $container->set(IdToken::class, static fn(): IdToken => new IdToken($container->get(Metadata::class)));
}

if (!$container->has(UserInfo::class)) {
    $container->set(UserInfo::class, static fn(): UserInfo => new UserInfo($container->get(ClientInterface::class)));
}

if (!$container->has(TransactionStoreInterface::class)) {
    $container->set(TransactionStoreInterface::class, static function () use ($container): TransactionStoreInterface {
        if (!app()->hasPlugin('naf/session')) {
            throw new ConfigurationException(
                'A browser login needs a session to bind it to one browser. '
                . 'Run "composer require naf/session", or bind your own '
                . TransactionStoreInterface::class . '.',
            );
        }

        return new SessionTransactions($container->get(Session::class));
    });
}

if (!$container->has(OAuth::class)) {
    $container->set(OAuth::class, static function () use ($container): OAuth {
        // auth:logins is the current home. oauth:providers is the older spelling
        // and still works; an application that used it keeps working unchanged.
        $logins = (array) config('auth:logins', []);
        $path   = 'auth:logins';

        if ($logins === []) {
            $logins = (array) config('oauth:providers', []);
            $path   = 'oauth:providers';
        }

        return new OAuth(
            providers: $logins,
            factory: static fn(ProviderConfig $provider): Flow => new Flow(
                provider: $provider,
                http: $container->get(ClientInterface::class),
                transactions: $container->get(TransactionStoreInterface::class),
                metadata: $container->get(Metadata::class),
                idToken: $container->get(IdToken::class),
                userInfo: $container->get(UserInfo::class),
                afterLogin: (string) config('oauth:after_login', '/'),

                // Asking for offline access is only honest where the answer will be
                // kept. Read here rather than in the Flow, which has no opinion
                // about storage.
                offlineAccess: config('oauth:tokens:store', false) === true,
            ),
            publicUrl: config('public_url'),
            configPath: $path,
        );
    });
}

if (!$container->has(AccountLinkStoreInterface::class)) {
    $container->set(AccountLinkStoreInterface::class, static function () use ($container): AccountLinkStoreInterface {
        if (!$container->has(PDO::class)) {
            throw new ConfigurationException(
                'The account link store needs a PDO connection bound to ' . PDO::class . '. '
                . 'Bind yours in the application bootstrap, or bind your own '
                . AccountLinkStoreInterface::class . ' instead.',
            );
        }

        return new PdoAccountLinks(
            connection: $container->get(PDO::class),
            table: (string) config('oauth:accounts:table', 'oauth_identities'),
        );
    });
}

if (!$container->has(Accounts::class)) {
    $container->set(Accounts::class, static function () use ($container): Accounts {
        $create = config('oauth:accounts:create');

        if ($create !== null && !is_callable($create)) {
            throw new ConfigurationException('oauth:accounts:create has to be callable.');
        }

        return new Accounts(
            links: $container->get(AccountLinkStoreInterface::class),
            auth: $container->get(Auth::class),

            // Which sources exist is Auth's own answer: the sole one is used
            // without being named, and naming one is only necessary once there
            // are several.
            configuredProvider: config('oauth:accounts:provider'),
            autoRegister: config('oauth:accounts:auto_register', false) === true,
            create: $create === null ? null : Closure::fromCallable($create),
        );
    });
}

if (!$container->has(Cipher::class)) {
    $container->set(Cipher::class, static fn(): Cipher => Cipher::fromKey(config('oauth:tokens:key')));
}

if (!$container->has(TokenStoreInterface::class)) {
    $container->set(TokenStoreInterface::class, static function () use ($container): TokenStoreInterface {
        if (config('oauth:tokens:store', false) !== true) {
            throw new ConfigurationException(
                'Provider tokens are not being kept. Set oauth:tokens:store to true if the '
                . 'application needs to call a provider on somebody\'s behalf, or bind your own '
                . TokenStoreInterface::class . '.',
            );
        }

        if (!$container->has(PDO::class)) {
            throw new ConfigurationException(
                'The provider token store needs a PDO connection bound to ' . PDO::class . '. '
                . 'Bind yours in the application bootstrap, or bind your own '
                . TokenStoreInterface::class . ' instead.',
            );
        }

        return new PdoTokens(
            connection: $container->get(PDO::class),
            cipher: $container->get(Cipher::class),
            table: (string) config('oauth:tokens:table', 'oauth_provider_tokens'),
        );
    });
}

if (!$container->has(Tokens::class)) {
    $container->set(Tokens::class, static fn(): Tokens => new Tokens(
        store: $container->get(TokenStoreInterface::class),
        providers: $container->get(OAuth::class),
        accounts: $container->get(Accounts::class),
        auth: $container->get(Auth::class),
    ));
}

if (app()->hasPlugin('naf/database')) {
    MigrationRegistry::addPath(__DIR__ . '/src/Migrations');
}

if (app()->hasPlugin('naf/cli')) {
    $commands = $container->get(CommandRegistry::class);
    $commands->add(DiscoverCommand::class);
    $commands->add(DoctorCommand::class);
}
