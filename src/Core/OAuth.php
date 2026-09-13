<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Core;

use Closure;
use NixPHP\OAuth\Client\Exception\ConfigurationException;
use NixPHP\OAuth\Client\Provider\ProviderConfig;

/**
 * The configured providers, built when somebody actually uses one.
 *
 * Resolving a provider reads its discovery document, so five configured
 * providers cost nothing until a visitor picks one. A broken configuration is
 * reported the first time that provider is reached, naming the key that is wrong.
 */
final class OAuth
{
    /** @var array<string, Flow> */
    private array $flows = [];

    /**
     * @param array<string, array<string, mixed>> $providers
     * @param Closure(ProviderConfig): Flow $factory
     */
    public function __construct(
        private readonly array $providers,
        private readonly Closure $factory,
        private readonly ?string $publicUrl,
        private readonly string $configPath = 'auth:logins',
    ) {}

    public function has(string $key): bool
    {
        return isset($this->providers[$key]);
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->providers);
    }

    public function provider(string $key): Flow
    {
        if (isset($this->flows[$key])) {
            return $this->flows[$key];
        }

        if (!isset($this->providers[$key])) {
            throw new ConfigurationException(
                'No login "' . $key . '" is configured under ' . $this->configPath . '. '
                . 'Configured: ' . (implode(', ', $this->names()) ?: 'none') . '.'
            );
        }

        if ($this->publicUrl === null || trim($this->publicUrl) === '') {
            throw new ConfigurationException(
                'public_url is required: every redirect URI is derived from it, and a request '
                . 'cannot be trusted to say where this application lives. '
                . 'Set it in app/config.php, for example "public_url" => "https://example.com".'
            );
        }

        return $this->flows[$key] = ($this->factory)(
            ProviderConfig::fromArray($key, $this->providers[$key], $this->publicUrl, $this->configPath)
        );
    }
}
