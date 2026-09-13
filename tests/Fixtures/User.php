<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use NixPHP\Auth\Identity\UserInterface;
use NixPHP\Auth\Identity\UserProfile;

/** An application's own user model, answering the contract the doctor checks for. */
final class User implements UserInterface
{
    public function __construct(
        private readonly string $id = '1',
        private readonly bool $active = true,
    ) {}

    public function getIdentifier(): string { return $this->id; }
    public function getRoles(): iterable { return []; }
    public function getPermissions(): iterable { return []; }
    public function isActive(): bool { return $this->active; }

    public function getProfile(): UserProfile
    {
        return new UserProfile(name: 'Somebody', email: 'somebody@example.test', emailVerified: true);
    }
}
