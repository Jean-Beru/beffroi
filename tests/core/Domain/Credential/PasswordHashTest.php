<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Credential;

use Heidi\Core\Domain\Credential\PasswordAlgorithm;
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
        $hash = new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'base64digest', [
            'salt' => 'base64salt',
            'iterations' => 27500,
        ]);

        // Then
        static::assertSame(PasswordAlgorithm::Pbkdf2Sha256, $hash->algorithm);
        static::assertSame(27500, $hash->parameters['iterations']);
    }

    #[Test]
    public function itRejectsAnEmptyDigest(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new PasswordHash(PasswordAlgorithm::Argon2id, '');
    }
}
