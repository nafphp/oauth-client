<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use NixPHP\Auth\Identity\IdentityInterface;

/** A local account, which can be suspended. */
final class Account implements IdentityInterface
{
    public function __construct(
        private readonly string $id,
        public bool $active = true,
    ) {}

    public function getIdentifier(): string { return $this->id; }
    public function getRoles(): iterable { return []; }
    public function getPermissions(): iterable { return []; }
}
