<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Migrations;

use Naf\Database\Core\AbstractMigration;
use PDO;

/**
 * The provider token table.
 *
 * Only needed once an application wants to call a provider's API on somebody's
 * behalf; a login stores nothing here. It is created regardless, because a table
 * nobody writes to costs nothing, and a migration that only runs after a
 * configuration change is a migration people forget to run.
 *
 * `access_token` and `refresh_token` hold ciphertext, which is why they are TEXT
 * rather than sized to what a provider currently issues.
 *
 * Named for whose tokens these are, because naf/oauth-server has an
 * oauth_tokens of its own and an application is perfectly entitled to be both a
 * client and a server.
 */
class OAuthProviderTokensMigration extends AbstractMigration
{
    public function up(PDO $connection): void
    {
        $connection->exec(
            <<<'SQL'
                CREATE TABLE IF NOT EXISTS oauth_provider_tokens
                (
                    link          CHAR(64)     NOT NULL PRIMARY KEY,
                    provider      VARCHAR(64)  NOT NULL,
                    issuer        VARCHAR(255) NOT NULL,
                    subject       VARCHAR(255) NOT NULL,
                    access_token  TEXT         NOT NULL,
                    refresh_token TEXT             NULL,
                    scope         TEXT         NOT NULL,
                    expires_at    INT              NULL,
                    updated_at    INT          NOT NULL
                )
            SQL,
        );

        // An issuer and a subject are case-sensitive identifiers, and MySQL's
        // default collation is not. The same reasoning as for oauth_identities,
        // and it matters more here: these two are what a ciphertext is bound to.
        if ($connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            foreach ([['issuer', 255], ['subject', 255], ['provider', 64]] as [$column, $length]) {
                $connection->exec(
                    'ALTER TABLE oauth_provider_tokens MODIFY ' . $column
                    . ' VARCHAR(' . $length . ') COLLATE utf8mb4_bin NOT NULL',
                );
            }
        }
    }

    public function down(PDO $connection): void
    {
        $connection->exec('DROP TABLE IF EXISTS oauth_provider_tokens');
    }
}
