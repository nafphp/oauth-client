<?php

declare(strict_types=1);

namespace Naf\OAuth\Client\Account;

use Closure;
use Naf\Auth\Auth;
use Naf\Auth\Identity\IdentityInterface;
use Naf\OAuth\Client\Core\Callback;
use Naf\OAuth\Client\Exception\ConfigurationException;
use Naf\OAuth\Client\Exception\OAuthException;
use Naf\OAuth\Client\Identity\ExternalIdentity;

/**
 * The one decision this plugin will not make for you, with everything around it
 * already made.
 *
 * A verified external identity does not say which of your accounts it is. Three
 * answers are possible, and only one of them is safe by default:
 *
 * - somebody linked it before  → sign that account in
 * - nobody did, and you allow it → create an account, then link it
 * - nobody did                  → refuse, and let them sign in and link it themselves
 *
 * What it deliberately never does is match on the e-mail address. Not even a
 * verified one: anybody who can make a provider assert an address can then walk
 * into the account that uses it. Attaching a second provider is therefore a
 * separate act, performed by somebody already signed in — see link().
 */
final class Accounts
{
    /** @param (Closure(ExternalIdentity): ?IdentityInterface)|null $create */
    public function __construct(
        private readonly AccountLinkStoreInterface $links,
        private readonly Auth $auth,
        private readonly ?string $configuredProvider = null,
        private readonly bool $autoRegister = false,
        private readonly ?Closure $create = null,
    ) {
    }

    /** Finish a verified callback, whichever kind it was. */
    public function complete(Callback $callback): IdentityInterface
    {
        return $callback->isLink() ? $this->link($callback) : $this->signIn($callback);
    }

    public function signIn(Callback $callback): IdentityInterface
    {
        $external = $callback->identity;
        $link     = $this->links->find($external->issuer, $external->subject);

        if ($link !== null) {
            $user = $this->auth->load($link->userProvider, $link->userId);

            if ($user === null) {
                // Deleted, locked, or its source is no longer registered. The link
                // stays: an account that cannot sign in today is not an account
                // somebody should have to attach again tomorrow.
                throw OAuthException::of('account_unavailable', 'The linked account cannot sign in.');
            }

            $this->auth->setIdentity($user, $link->userProvider);

            return $user;
        }

        if (!$this->autoRegister) {
            throw OAuthException::of(
                'not_linked',
                'No account is linked to that login yet. Sign in and connect it, or turn on oauth:accounts:auto_register.',
            );
        }

        if ($this->create === null) {
            throw new ConfigurationException(
                'oauth:accounts:auto_register is on, but oauth:accounts:create is not set. '
                . 'Give it a function that turns an ExternalIdentity into one of your accounts.',
            );
        }

        $source = $this->source();
        $create = $this->create;

        // One act with two halves. If the link fails, the account goes with it —
        // otherwise a failed first login leaves an account nothing points at, and
        // the next attempt makes another one beside it.
        $identifier = $this->links->transaction(function () use ($create, $external, $source): string {
            $created = $create($external);

            if ($created === null) {
                throw OAuthException::of('registration_refused', 'No account was created for that login.');
            }

            $this->links->link($external, $source, $created->getIdentifier());

            return $created->getIdentifier();
        });

        // Read back through the configured account source rather than trusting the
        // object the factory returned: what signs in has to be what the next
        // request will load, and the source is what decides who may sign in at all.
        $user = $this->auth->load($source, $identifier);

        if ($user === null) {
            throw OAuthException::of('registration_refused', 'The new account cannot sign in.');
        }

        $this->auth->setIdentity($user, $source);

        return $user;
    }

    /**
     * Attach this provider to the account that started the link.
     *
     * The person who finishes has to be the person who began, which is why the
     * login recorded them. Nobody is signed in here — they already were.
     */
    public function link(Callback $callback): IdentityInterface
    {
        $initiator = $callback->initiator;

        if ($initiator === null) {
            throw OAuthException::of('no_initiator', 'That login was not started as a link.');
        }

        $current = $this->auth->user();

        if ($current === null
            || $this->auth->providerName() !== $initiator['provider']
            || !hash_equals($initiator['id'], $current->getIdentifier())) {
            throw OAuthException::of('initiator_mismatch', 'A link has to be finished by whoever started it.');
        }

        $external = $callback->identity;
        $existing = $this->links->find($external->issuer, $external->subject);

        if ($existing !== null) {
            if ($existing->userProvider === $initiator['provider']
                && hash_equals($initiator['id'], $existing->userId)) {
                return $current; // Already attached to this very account.
            }

            throw OAuthException::of('already_linked', 'That provider account belongs to somebody else.');
        }

        $this->links->link($external, $initiator['provider'], $initiator['id']);

        return $current;
    }

    /**
     * Every provider an account can currently sign in with.
     *
     * @return list<AccountLink>
     */
    public function of(IdentityInterface $user, ?string $userProvider = null): array
    {
        return $this->links->forAccount($userProvider ?? $this->source(), $user->getIdentifier());
    }

    /**
     * Which naf/auth source owns the accounts external logins map onto.
     *
     * Asked of the registry itself rather than of the configuration it was
     * usually filled from — a source added imperatively in a bootstrap is just as
     * real, and a second copy of that list would only ever disagree.
     */
    private function source(): string
    {
        if ($this->configuredProvider !== null && $this->configuredProvider !== '') {
            return $this->configuredProvider;
        }

        $registered = $this->auth->providers();

        if (count($registered) === 1) {
            return $registered[0];
        }

        throw new ConfigurationException($registered === []
            ? 'No account source is registered with naf/auth. Register one before signing anybody in.'
            : 'Several account sources are registered (' . implode(', ', $registered) . '). '
              . 'Name the one that owns external logins in oauth:accounts:provider.');
    }
}
