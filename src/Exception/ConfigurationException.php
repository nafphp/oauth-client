<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Client\Exception;

use LogicException;

/**
 * The setup cannot work, and no login should be attempted with it.
 *
 * Raised while resolving configuration, never in reaction to what a provider or a
 * browser sent. It is addressed to whoever wired the application, so it says what
 * is missing and where it belongs.
 */
final class ConfigurationException extends LogicException
{
}
