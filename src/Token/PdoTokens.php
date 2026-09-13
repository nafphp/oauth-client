<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Token;

use InvalidArgumentException;
use PDO;
use PDOException;
use PDOStatement;
use RuntimeException;

/**
 * Provider tokens in an existing PDO connection, encrypted at rest.
 *
 * Addressed the same way an account link is — by a hash of `(issuer, subject)` as
 * the primary key — so one external identity has one set of tokens, enforced by
 * the database rather than by whoever calls it. That hash is also what the
 * ciphertexts are bound to, which is why a row cannot be copied onto another.
 *
 * The scope, the expiry and the issuer stay in the clear: knowing that somebody
 * granted calendar access until Tuesday is not the same as being able to use it,
 * and leaving them readable is what makes the table queryable at all.
 */
final class PdoTokens implements TokenStoreInterface
{
    private readonly string $table;

    public function __construct(
        private readonly PDO $connection,
        private readonly Cipher $cipher,
        string $table = 'oauth_provider_tokens',
    ) {
        $this->table = $this->quote($table);
    }

    public function find(string $issuer, string $subject): ?ProviderToken
    {
        $key = self::key($issuer, $subject);

        $row = $this->execute(
            'SELECT provider, issuer, subject, access_token, refresh_token, scope, expires_at FROM '
            . $this->table . ' WHERE link = :link',
            ['link' => $key],
        )->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row)) {
            return null;
        }

        $refresh = $row['refresh_token'];

        return new ProviderToken(
            provider: (string) $row['provider'],
            issuer: (string) $row['issuer'],
            subject: (string) $row['subject'],
            accessToken: $this->cipher->decrypt((string) $row['access_token'], $key),
            refreshToken: is_string($refresh) && $refresh !== '' ? $this->cipher->decrypt($refresh, $key) : null,
            scope: self::scopes((string) $row['scope']),
            expiresAt: $row['expires_at'] === null ? null : (int) $row['expires_at'],
        );
    }

    public function put(ProviderToken $token): void
    {
        $key = self::key($token->issuer, $token->subject);

        $values = [
            'link'          => $key,
            'provider'      => $token->provider,
            'issuer'        => $token->issuer,
            'subject'       => $token->subject,
            'access_token'  => $this->cipher->encrypt($token->accessToken, $key),
            'refresh_token' => $token->refreshToken === null ? null : $this->cipher->encrypt($token->refreshToken, $key),
            'scope'         => implode(' ', $token->scope),
            'expires_at'    => $token->expiresAt === null ? null : (string) $token->expiresAt,
            'updated_at'    => (string) time(),
        ];

        try {
            $this->execute(
                'INSERT INTO ' . $this->table
                . ' (link, provider, issuer, subject, access_token, refresh_token, scope, expires_at, updated_at)'
                . ' VALUES (:link, :provider, :issuer, :subject, :access_token, :refresh_token, :scope, :expires_at, :updated_at)',
                $values,
            );

            return;
        } catch (PDOException $e) {
            // Only "it is already there" is handled here; a dropped connection or a
            // value too long for its column is not an update waiting to happen.
            //
            // The SQLSTATE comes from errorInfo: Throwable::getCode() is declared
            // int, and PDO puts a five-character string there.
            $state = is_string($e->errorInfo[0] ?? null) ? $e->errorInfo[0] : '';

            if ($state !== '23000' && $state !== '23505') {
                throw $e;
            }
        }

        // Insert-then-update rather than update-then-insert, because "did the
        // update match a row?" has no portable answer: MySQL's rowCount() counts
        // rows it changed, so writing the same values back reads as a miss.
        unset($values['link']);

        $this->execute(
            'UPDATE ' . $this->table . ' SET provider = :provider, issuer = :issuer, subject = :subject,'
            . ' access_token = :access_token, refresh_token = :refresh_token, scope = :scope,'
            . ' expires_at = :expires_at, updated_at = :updated_at WHERE link = :link',
            $values + ['link' => $key],
        );
    }

    public function forget(string $issuer, string $subject): void
    {
        $this->execute(
            'DELETE FROM ' . $this->table . ' WHERE link = :link',
            ['link' => self::key($issuer, $subject)],
        );
    }

    /** @param array<string, string|null> $parameters */
    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->connection->prepare($sql);

        if ($statement === false || !$statement->execute($parameters)) {
            throw new RuntimeException('The provider token store could not be read or written.');
        }

        return $statement;
    }

    /** @return list<string> */
    private static function scopes(string $granted): array
    {
        return array_values(array_filter(explode(' ', trim($granted)), static fn(string $s): bool => $s !== ''));
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
