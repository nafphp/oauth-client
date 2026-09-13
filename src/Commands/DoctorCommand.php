<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Commands;

use NixPHP\Auth\Auth;
use NixPHP\Auth\Identity\UserInterface;
use NixPHP\CLI\Core\{AbstractCommand, Input, Output};
use NixPHP\OAuth\Client\Account\AccountLinkStoreInterface;
use NixPHP\OAuth\Client\Core\OAuth;
use NixPHP\OAuth\Client\Token\Cipher;
use NixPHP\OAuth\Client\Token\TokenStoreInterface;
use PDO;
use Throwable;
use function NixPHP\app;
use function NixPHP\config;

/**
 * Everything that has to be true before the first login, checked at once.
 *
 * These are the conditions that otherwise surface as a failed sign-in, halfway
 * through a redirect, in front of a person who cannot do anything about it. A
 * command can say them plainly instead, and say them before anybody tries.
 *
 * It never prints a secret. Whether one is set is worth knowing; what it is, is
 * not worth putting in a terminal, a screenshot or a support ticket.
 */
class DoctorCommand extends AbstractCommand
{
    public const string NAME = 'oauth:doctor';

    private int $problems = 0;

    protected function configure(): void
    {
        $this
            ->setTitle('Check the login setup')
            ->setDescription('Verify dependencies, connection, user model, tables, URLs and each configured login.');
    }

    public function run(Input $input, Output $output): int
    {
        $output->writeEmptyLine();

        $this->dependencies($output);
        $this->publicUrl($output);
        $this->users($output);
        $this->links($output);
        $this->tokens($output);
        $this->logins($output);

        $output->writeEmptyLine();
        $output->writeLine($this->problems === 0
            ? '  Ready to sign people in.'
            : '  ' . $this->problems . ' thing(s) to fix before the first login.',
            $this->problems === 0 ? 'ok' : 'error');
        $output->writeEmptyLine();

        return $this->problems === 0 ? self::SUCCESS : self::ERROR;
    }

    // ---------------------------------------------------------------- Checks

    private function dependencies(Output $output): void
    {
        foreach (['nixphp/auth' => true, 'nixphp/session' => true, 'nixphp/client' => false,
                  'nixphp/database' => false, 'nixphp/view' => false] as $plugin => $required) {
            $installed = app()->hasPlugin($plugin);

            $this->line($output, $plugin, match (true) {
                $installed  => 'installed',
                $required   => 'MISSING — a browser login cannot work without it',
                default     => 'not installed (optional)',
            }, $installed || !$required);
        }
    }

    private function publicUrl(Output $output): void
    {
        $url = config('public_url');

        if (!is_string($url) || trim($url) === '') {
            $this->line($output, 'public_url', 'MISSING — every callback URL is derived from it', false);

            return;
        }

        $this->line($output, 'public_url', $url, str_starts_with($url, 'https://') || self::isLoopback($url));
    }

    private function users(Output $output): void
    {
        $model     = config('auth:users:model');
        $providers = (array) config('auth:providers', []);

        if (!is_string($model) && $providers === []) {
            $this->line($output, 'auth:users:model', 'MISSING — nothing says where your accounts live', false);

            return;
        }

        if (is_string($model)) {
            $this->line($output, 'auth:users:model', $model, class_exists($model));

            $this->line(
                $output,
                'UserInterface',
                is_a($model, UserInterface::class, true)
                    ? 'implemented'
                    : 'not implemented — suspension and profile claims will be skipped',
                is_a($model, UserInterface::class, true),
            );
        }

        try {
            $registered = app()->container()->get(Auth::class)->providers();
            $this->line($output, 'account sources', implode(', ', $registered) ?: 'none', $registered !== []);
        } catch (Throwable $e) {
            $this->line($output, 'account sources', 'cannot resolve: ' . $e->getMessage(), false);
        }
    }

    private function links(Output $output): void
    {
        try {
            app()->container()->get(AccountLinkStoreInterface::class)->find('https://probe.invalid', 'probe');
            $this->line($output, 'oauth_identities', 'present', true);
        } catch (Throwable $e) {
            $this->line($output, 'oauth_identities', 'missing — run "nix db:migrate up"', false);
        }
    }

    /**
     * Whether this installation can keep what a provider issues.
     *
     * Nothing here is required for a login, so an installation that keeps
     * nothing passes by saying so. Once it does keep tokens, all three have to
     * hold: the extension that encrypts them, a key to encrypt them with, and
     * somewhere to put them.
     */
    private function tokens(Output $output): void
    {
        if (config('oauth:tokens:store', false) !== true) {
            $this->line($output, 'oauth:tokens:store', 'off — signing in only, nothing is kept', true);

            return;
        }

        $this->line($output, 'oauth:tokens:store', 'on — provider tokens are kept for API calls', true);

        $sodium = function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt');

        $this->line($output, 'ext-sodium', $sodium
            ? 'loaded'
            : 'MISSING — provider tokens are encrypted before they are written', $sodium);

        try {
            Cipher::fromKey(config('oauth:tokens:key'));
            $this->line($output, 'oauth:tokens:key', 'set', true);
        } catch (Throwable $e) {
            // The message says how to make a key. The key itself is never printed
            // here, for the same reason no other secret is.
            $this->line($output, 'oauth:tokens:key', self::reason($e), false);

            // And the table cannot be looked at from here without one: the store
            // needs the cipher to be built at all. Reporting it as missing would
            // send somebody off to run a migration that has already run.
            return;
        }

        try {
            app()->container()->get(TokenStoreInterface::class)->find('https://probe.invalid', 'probe');
            $this->line($output, 'oauth_provider_tokens', 'present', true);
        } catch (Throwable $e) {
            $this->line($output, 'oauth_provider_tokens', 'missing — run "nix db:migrate up"', false);
        }
    }

    private function logins(Output $output): void
    {
        $registry = app()->container()->get(OAuth::class);
        $names    = $registry->names();

        if ($names === []) {
            $this->line($output, 'logins', 'none configured under auth:logins', false);

            return;
        }

        foreach ($names as $name) {
            $output->writeEmptyLine();

            try {
                $flow = $registry->provider($name);
            } catch (Throwable $e) {
                $this->line($output, $name, self::reason($e), false);
                continue;
            }

            $this->line($output, $name, $flow->label(), true);

            try {
                // Only the metadata. Starting an actual login would need a session,
                // which a command line does not have and should not invent.
                $document = $flow->metadata();

                // A provider without OpenID Connect is never contacted here: its
                // endpoints come from the configuration and its issuer is one we
                // assigned. Reporting that as "belongs to …" would read as proof
                // that it answered, which is the one thing this line must not
                // claim without having asked.
                $this->line($output, '  metadata', match (true) {
                    !$flow->isOidc() => 'no discovery document — endpoints come from the configuration',
                    is_string($document['issuer'] ?? null) => 'belongs to ' . $document['issuer'],
                    default => 'reachable',
                }, true);
            } catch (Throwable $e) {
                $this->line($output, '  metadata', self::reason($e), false);
            }

            // Asked of the provider rather than rebuilt, so an application that
            // set callback_url itself is told to register the one it will send.
            $this->line($output, '  callback', $flow->redirectUri(), true);
        }
    }

    // ---------------------------------------------------------------- Output

    private function line(Output $output, string $label, string $value, bool $good): void
    {
        if (!$good) {
            $this->problems++;
        }

        $output->writeLine('  ' . ($good ? '+' : '!') . ' ' . str_pad($label, 22) . $value, $good ? null : 'error');
    }

    /** Never the message of a configuration exception verbatim — it may quote a value. */
    private static function reason(Throwable $e): string
    {
        return property_exists($e, 'reason') && is_string($e->reason)
            ? $e->reason
            : $e->getMessage();
    }

    private static function isLoopback(string $url): bool
    {
        return in_array(parse_url($url, PHP_URL_HOST), ['localhost', '127.0.0.1', '[::1]'], true);
    }
}
