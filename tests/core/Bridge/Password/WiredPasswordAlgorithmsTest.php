<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Password;

use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0002
 */
final class WiredPasswordAlgorithmsTest extends TestCase
{
    #[Test]
    public function aStoredNameIsReadBackAsTheAlgorithmTheWiringHolds(): void
    {
        // Given
        $algorithms = new WiredPasswordAlgorithms([new Argon2id(), new Bcrypt()]);

        // When
        $algorithm = $algorithms->named(Bcrypt::NAME);

        // Then
        static::assertInstanceOf(Bcrypt::class, $algorithm);
    }

    #[Test]
    public function theFirstWiredAlgorithmIsWhatANewHashIsMadeWith(): void
    {
        // Given
        $algorithms = new WiredPasswordAlgorithms([new Bcrypt(), new Argon2id()]);

        // When / Then
        static::assertSame(Bcrypt::NAME, $algorithms->defaultAlgorithm()->name());
    }

    #[Test]
    public function aNameNothingWiredAccountsForIsRefused(): void
    {
        // Given
        $algorithms = new WiredPasswordAlgorithms([new Argon2id()]);

        // Then
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessageIs('This provider accounts for no password hash made with "scrypt"; it accounts for argon2id.');

        // When
        $algorithms->named('scrypt');
    }

    #[Test]
    public function anAlgorithmWiredTwiceIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The algorithm "argon2id" is wired twice.');

        // When
        new WiredPasswordAlgorithms([new Argon2id(), new Argon2id()]);
    }

    #[Test]
    public function aProviderThatHashesNoPasswordIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider hashes a password with at least one algorithm.');

        // When
        new WiredPasswordAlgorithms([]);
    }
}
