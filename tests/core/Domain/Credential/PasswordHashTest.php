<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Credential;

use Heidi\Core\Bridge\Password\Algorithm\Argon2id;
use Heidi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PasswordHashTest extends TestCase
{
    /**
     * Decision 0002: no password hash without an identified algorithm.
     */
    #[Test]
    public function itAlwaysNamesItsAlgorithmAndMayCarryParameters(): void
    {
        // When
        $hash = new PasswordHash(new Pbkdf2Sha256(), 'base64digest', [
            'salt' => 'base64salt',
            'iterations' => 27500,
        ]);

        // Then
        static::assertSame(Pbkdf2Sha256::NAME, $hash->algorithm->name());
        static::assertSame(27500, $hash->parameters['iterations']);
    }

    #[Test]
    public function itRejectsAnEmptyDigest(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new PasswordHash(new Argon2id(), '');
    }
}
