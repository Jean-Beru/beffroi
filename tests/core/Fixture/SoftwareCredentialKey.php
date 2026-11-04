<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

/**
 * WebAuthn Level 3 §6.5.1.1
 */
interface SoftwareCredentialKey
{
    public function algorithm(): int;

    public function cosePublicKey(): string;

    public function sign(string $data): string;
}
