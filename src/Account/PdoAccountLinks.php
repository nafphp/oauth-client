<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Account;

use InvalidArgumentException;
use Naf\OAuth\Client\Exception\OAuthException;
use Naf\OAuth\Client\Identity\ExternalIdentity;
use PDO;
use PDOException;
use PDOStatement;
use RuntimeException;
use Throwable;

/**
 * Account links in an existing PDO connection.
 *
 * Rows are addressed by a hash of `(issuer, subject)`, which is the primary key.
 * That makes the uniqueness the database's job rather than the caller's: two
 * simultaneous first logins cannot both create a link, whatever the application
 * checked a moment earlier.
 */
final class PdoAccountLinks implements AccountLinkStoreInterface
{
    private readonly string $table;

    public function __construct(
        private readonly PDO $connection,
        string $table = 'oauth_identities',
    ) {
        $this->table = $this->quote($table);
    }

    public function find(string $issuer, string $subject): ?AccountLink
    {
        $row = $this->execute(
            'SELECT provider, issuer, subject, user_provider, user_id FROM ' . $this->table . ' WHERE link = :link',
            ['link' => self::key($issuer, $subject)],
        )->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? self::hydrate($row) : null;
    }

    public function link(ExternalIdentity $identity, string $userProvider, string $userId): AccountLink
    {
        if ($userProvider === '' || $userId === '') {
            throw new InvalidArgumentException('A link needs an account to point at.');
        }

        try {
            $this->execute(
                'INSERT INTO ' . $this->table
                . ' (link, provider, issuer, subject, user_provider, user_id, created_at)'
                . ' VALUES (:link, :provider, :issuer, :subject, :user_provider, :user_id, :created_at)',
                [
                    'link'          => self::key($identity->issuer, $identity->subject),
                    'provider'      => $identity->provider,
                    'issuer'        => $identity->issuer,
                    'subject'       => $identity->subject,
                    'user_provider' => $userProvider,
                    'user_id'       => $userId,
                    'created_at'    => (string) time(),
                ],
            );
        } catch (PDOException $e) {
            // Only an integrity violation means somebody won the race. A dropped
            // connection or a value too long for its column is not "already
            // linked", and reporting it as such hides a broken installation
            // behind a message that sounds like ordinary use.
            //
            // The SQLSTATE comes from errorInfo: Throwable::getCode() is declared
            // int, and PDO puts a five-character string there.
            $state = is_string($e->errorInfo[0] ?? null) ? $e->errorInfo[0] : '';

            if ($state === '23000' || $state === '23505') {
                throw OAuthException::of('already_linked', 'That provider account is already linked.', $e);
            }

            throw $e;
        }

        return new AccountLink(
            $identity->provider,
            $identity->issuer,
            $identity->subject,
            $userProvider,
            $userId,
        );
    }

    public function unlink(string $issuer, string $subject): void
    {
        $this->execute(
            'DELETE FROM ' . $this->table . ' WHERE link = :link',
            ['link' => self::key($issuer, $subject)],
        );
    }

    public function transaction(callable $work): mixed
    {
        // A nested call joins whatever is already open rather than starting a
        // second one that the driver would refuse.
        if ($this->connection->inTransaction()) {
            return $work();
        }

        $this->connection->beginTransaction();

        try {
            $result = $work();
        } catch (Throwable $e) {
            // Committing after the try rather than inside it is what makes this
            // rollback unconditional: reaching here means the work failed and
            // nothing has been committed.
            $this->connection->rollBack();

            throw $e;
        }

        $this->connection->commit();

        return $result;
    }

    public function forAccount(string $userProvider, string $userId): array
    {
        $rows = $this->execute(
            'SELECT provider, issuer, subject, user_provider, user_id FROM ' . $this->table
            . ' WHERE user_provider = :user_provider AND user_id = :user_id ORDER BY created_at',
            ['user_provider' => $userProvider, 'user_id' => $userId],
        )->fetchAll(PDO::FETCH_ASSOC);

        return array_map(self::hydrate(...), is_array($rows) ? $rows : []);
    }

    /** @param array<string, string> $parameters */
    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->connection->prepare($sql);

        if ($statement === false || !$statement->execute($parameters)) {
            throw new RuntimeException('The account link store could not be read or written.');
        }

        return $statement;
    }

    /** @param array<string, mixed> $row */
    private static function hydrate(array $row): AccountLink
    {
        return new AccountLink(
            (string) $row['provider'],
            (string) $row['issuer'],
            (string) $row['subject'],
            (string) $row['user_provider'],
            (string) $row['user_id'],
        );
    }

    /** Fixed width, and the same on every database. The parts stay in their own columns. */
    private static function key(string $issuer, string $subject): string
    {
        return hash('sha256', $issuer . "\0" . $subject);
    }

    private function quote(string $identifier): string
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $identifier) !== 1) {
            throw new InvalidArgumentException('Use a simple table name: ' . $identifier);
        }

        $quote = $this->connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? '`' : '"';

        return $quote . $identifier . $quote;
    }
}
