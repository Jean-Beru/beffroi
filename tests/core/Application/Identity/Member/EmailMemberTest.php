<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity\Member;

use Beffroi\Core\Application\Identity\Member\EmailMember;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.1
 */
final class EmailMemberTest extends TestCase
{
    #[Test]
    public function theAddressThePersonHoldsSaidAgainKeepsItsVerification(): void
    {
        // Given
        $alice = Fixtures::user();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        new EmailMember()->say($alice, 'alice@acme.example', Fixtures::now());

        // Then
        static::assertTrue($alice->emailVerified);
    }

    #[Test]
    public function nullTakesTheAddressAway(): void
    {
        // Given
        $alice = Fixtures::user();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        // When
        new EmailMember()->say($alice, null, Fixtures::now());

        // Then
        static::assertSame([null, false], [$alice->email, $alice->emailVerified]);
    }

    #[Test]
    public function whatIsNotAnAddressIsRefused(): void
    {
        // Given
        $alice = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('"alice" is not a valid email address.');

        // When
        new EmailMember()->say($alice, 'alice', Fixtures::now());
    }
}
