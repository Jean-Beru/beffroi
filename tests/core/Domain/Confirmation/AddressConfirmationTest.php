<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Confirmation;

use Beffroi\Core\Domain\Confirmation\PhoneNumberConfirmation;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0026
 */
final class AddressConfirmationTest extends TestCase
{
    #[Test]
    public function aConfirmationExpiresAfterItWasSent(): void
    {
        // Given
        $hasher = new FakePasswordHasher();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A confirmation expires after it was sent.');

        // When
        new PhoneNumberConfirmation(Uuid::v7(), Fixtures::user(), $hasher->hash('code'), $hasher->hash('link'), Fixtures::now(), Fixtures::now());
    }

    #[Test]
    public function aConfirmationIsSpentOnce(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $confirmation = new PhoneNumberConfirmation(
            Uuid::v7(),
            Fixtures::user(),
            $hasher->hash('code'),
            $hasher->hash('link'),
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
        $confirmation->spend(Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This confirmation is spent already.');

        // When
        $confirmation->spend(Fixtures::now());
    }
}
