<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Migrations;

use Naf\Database\Core\AbstractMigration;
use PDO;
use PDOException;

/**
 * The account link table.
 *
 * Unquoted lowercase identifiers and an INT timestamp, so the same statement runs
 * on MySQL, PostgreSQL and SQLite. `link` is the hash of (issuer, subject) and is
 * the primary key, which is what makes one external identity belong to exactly
 * one account — enforced by the database rather than by whoever calls it.
 */
class OAuthIdentitiesMigration extends AbstractMigration
{
    public function up(PDO $connection): void
    {
        $connection->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS oauth_identities
            (
                link          CHAR(64)     NOT NULL PRIMARY KEY,
                provider      VARCHAR(64)  NOT NULL,
                issuer        VARCHAR(255) NOT NULL,
                subject       VARCHAR(255) NOT NULL,
                user_provider VARCHAR(64)  NOT NULL,
                user_id       VARCHAR(190) NOT NULL,
                created_at    INT          NOT NULL
            )
        SQL
        );

        // An issuer and a subject are case-sensitive identifiers, and MySQL's
        // default collation is not. Without this, two distinct subjects collide on
        // insert and one presented with its case mangled still matches.
        if ($connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            foreach ([['issuer', 255], ['subject', 255], ['provider', 64]] as [$column, $length]) {
                $connection->exec(
                    'ALTER TABLE oauth_identities MODIFY ' . $column
                    . ' VARCHAR(' . $length . ') COLLATE utf8mb4_bin NOT NULL'
                );
            }
        }

        $this->createIndex(
            $connection,
            'CREATE INDEX idx_oauth_identities_account ON oauth_identities (user_provider, user_id)',
        );
    }

    public function down(PDO $connection): void
    {
        $connection->exec('DROP TABLE IF EXISTS oauth_identities');
    }

    private function createIndex(PDO $connection, string $sql): void
    {
        try {
            $connection->exec($sql);
        } catch (PDOException $exception) {
            // Already there. MySQL says 1061, SQLite and PostgreSQL say so in words.
            if ($exception->getCode() !== '42000'
                && !str_contains(strtolower($exception->getMessage()), 'already exists')) {
                throw $exception;
            }
        }
    }
}
