<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Commands;

use NixPHP\CLI\Core\AbstractCommand;
use NixPHP\CLI\Core\Input;
use NixPHP\CLI\Core\Output;
use NixPHP\OAuth\Client\Core\Metadata;
use NixPHP\OAuth\Client\Core\OAuth;
use Throwable;
use function NixPHP\app;

/**
 * Check a configured provider, and say what to register with it.
 *
 * Endpoints and keys are read from the provider at run time, so there is no
 * config block to paste anywhere. What a person does still have to do by hand is
 * register the callback URL — so this prints it, next to proof that the rest of
 * the setup actually resolves. It warms the cache on the way through.
 */
class DiscoverCommand extends AbstractCommand
{
    public const string NAME = 'oauth:discover';

    protected function configure(): void
    {
        $this
            ->setTitle('Check an OAuth provider')
            ->setDescription('Read a configured provider\'s metadata and print the callback URL to register with it.')
            ->addArgument('provider', optional: true);
    }

    public function run(Input $input, Output $output): int
    {
        $registry = app()->container()->get(OAuth::class);
        $wanted   = $input->getArgument('provider');
        $names    = $wanted !== null ? [$wanted] : $registry->names();

        if ($names === []) {
            $output->writeLine('No logins are configured under auth:logins.', 'error');

            return self::ERROR;
        }

        $failed = false;

        foreach ($names as $name) {
            $failed = !$this->report($name, $registry, $output) || $failed;
        }

        return $failed ? self::ERROR : self::SUCCESS;
    }

    private function report(string $name, OAuth $registry, Output $output): bool
    {
        $output->writeEmptyLine();

        try {
            // Everything comes from the provider the registry built. Resolving the
            // configuration a second time here meant reading it from one place
            // while the application read it from another, and the two drifted:
            // this looked for logins where they have not lived since auth:logins.
            $flow     = $registry->provider($name);
            $document = $flow->metadata();
            $jwksUri  = $document['jwks_uri'] ?? null;

            // A provider without OpenID Connect publishes no keys, and asking for
            // them anyway is how a working setup gets reported as broken.
            $keys = is_string($jwksUri) && $jwksUri !== ''
                ? app()->container()->get(Metadata::class)->jwks($jwksUri)
                : null;
        } catch (Throwable $e) {
            $output->writeLine('  ' . $name, 'error');
            $output->writeLine('  ' . $e->getMessage());

            return false;
        }

        $output->writeLine('  ' . $flow->label(), 'ok');
        $this->line($output, 'Issuer', (string) ($document['issuer'] ?? '—'));
        $this->line($output, 'Authorization', (string) ($document['authorization_endpoint'] ?? '—'));
        $this->line($output, 'Token', (string) ($document['token_endpoint'] ?? '—'));
        $this->line($output, 'Signing keys', $keys === null
            ? 'none — this provider does not speak OpenID Connect'
            : (string) count((array) ($keys['keys'] ?? [])));
        $output->writeEmptyLine();
        $output->writeLine('  Register this callback URL with the provider:');
        $output->writeLine('  ' . $flow->redirectUri(), 'ok');

        return true;
    }

    private function line(Output $output, string $label, string $value): void
    {
        $output->writeLine('  ' . str_pad($label, 16) . $value);
    }
}
