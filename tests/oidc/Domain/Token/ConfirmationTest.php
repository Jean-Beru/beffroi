<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Domain\Token\Confirmation;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7800 §3.1 and RFC 8705 §3.1: what a token is bound to, written as "cnf" and read back the same
 * way, whichever shape the token has.
 */
final class ConfirmationTest extends TestCase
{
    /**
     * RFC 8705 §3.1: "x5t#S256" is the SHA-256 thumbprint of the DER encoding of the certificate.
     */
    #[Test]
    public function itIsTheThumbprintOfTheCertificatePresented(): void
    {
        // Given
        $certificate = Certificates::client();

        // When
        $confirmation = Confirmation::ofCertificate($certificate);

        // Then
        static::assertSame($certificate->x5tS256(), $confirmation->certificateThumbprint);
        static::assertSame([
            'cnf' => [
                'x5t#S256' => $certificate->x5tS256(),
            ],
        ], $confirmation->toClaims());
    }

    #[Test]
    public function itReadsBackTheClaimItWrote(): void
    {
        // Given
        $written = Confirmation::ofCertificate(Certificates::client());

        // When
        $read = Confirmation::fromClaims($written->toClaims());

        // Then
        static::assertEquals($written, $read);
    }

    #[Test]
    public function claimsWithoutAConfirmationAreABearerToken(): void
    {
        // When
        $confirmation = Confirmation::fromClaims([
            'sub' => 'alice',
        ]);

        // Then
        static::assertNull($confirmation);
    }

    #[Test]
    #[DataProvider('provideUnreadableConfirmations')]
    public function aConfirmationThatNamesNothingIsRefused(mixed $cnf): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The "cnf" of an access token of this provider names the thumbprint of a certificate (RFC 8705 section 3.1).');

        // When
        Confirmation::fromClaims([
            'cnf' => $cnf,
        ]);
    }

    /**
     * RFC 8705 §3: the token is honoured by whoever presents the certificate again.
     */
    #[Test]
    public function itIsPresentedByTheCertificateItNames(): void
    {
        // Given
        $confirmation = Confirmation::ofCertificate(Certificates::client());

        // When / Then
        static::assertTrue($confirmation->isPresentedBy(Certificates::client()));
    }

    #[Test]
    public function anotherCertificateDoesNotPresentIt(): void
    {
        // Given
        $confirmation = Confirmation::ofCertificate(Certificates::client());

        // When / Then
        static::assertFalse($confirmation->isPresentedBy(Certificates::other()));
    }

    /**
     * A bound token replayed as a bearer token opens nothing.
     */
    #[Test]
    public function aRequestWithoutACertificateDoesNotPresentIt(): void
    {
        // Given
        $confirmation = Confirmation::ofCertificate(Certificates::client());

        // When / Then
        static::assertFalse($confirmation->isPresentedBy(null));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideUnreadableConfirmations(): iterable
    {
        yield 'a thumbprint that is not a string' => [[
            'x5t#S256' => 42,
        ]];

        yield 'an empty thumbprint' => [[
            'x5t#S256' => '',
        ]];

        yield 'a confirmation of another kind' => [[
            'jkt' => 'a-key-thumbprint',
        ]];

        yield 'a confirmation that is not an object' => ['x5t#S256'];
    }
}
