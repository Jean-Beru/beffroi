<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Domain\Token\ConfirmationInterface;
use Heidi\Oidc\Domain\Token\Confirmations;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7800 §3.1, RFC 8705 §3.1 and RFC 9449 §6.1: what a token is bound to, written as "cnf" and read
 * back the same way, whichever shape the token has and whichever kind the binding is.
 */
final class ConfirmationsTest extends TestCase
{
    /**
     * RFC 7638 §3.1: the base64url of a SHA-256, the shape of every thumbprint here.
     */
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    /**
     * RFC 8705 §3.1: "x5t#S256" is the SHA-256 thumbprint of the DER encoding of the certificate.
     */
    #[Test]
    public function aCertificateIsNamedByItsThumbprint(): void
    {
        // Given
        $certificate = Certificates::client();

        // When
        $confirmation = CertificateConfirmation::ofCertificate($certificate);

        // Then
        static::assertSame($certificate->x5tS256(), $confirmation->value());
        static::assertSame(TokenResponse::BEARER, $confirmation->scheme());
        static::assertSame([
            'cnf' => [
                'x5t#S256' => $certificate->x5tS256(),
            ],
        ], $confirmation->toClaims());
    }

    /**
     * RFC 9449 §6.1: "jkt" is the JWK thumbprint of the key, and the token is presented under the DPoP
     * scheme from then on (§7.1).
     */
    #[Test]
    public function aKeyIsNamedByItsJwkThumbprint(): void
    {
        // When
        $confirmation = new KeyConfirmation(self::THUMBPRINT);

        // Then
        static::assertSame(self::THUMBPRINT, $confirmation->value());
        static::assertSame('DPoP', $confirmation->scheme());
        static::assertSame([
            'cnf' => [
                'jkt' => self::THUMBPRINT,
            ],
        ], $confirmation->toClaims());
    }

    #[Test]
    #[DataProvider('provideConfirmations')]
    public function itReadsBackTheClaimItWrote(ConfirmationInterface $written): void
    {
        // When
        $read = Confirmations::fromClaims($written->toClaims());

        // Then
        static::assertEquals($written, $read);
    }

    #[Test]
    public function claimsWithoutAConfirmationAreABearerToken(): void
    {
        // When
        $confirmation = Confirmations::fromClaims([
            'sub' => 'alice',
        ]);

        // Then
        static::assertNull($confirmation);
    }

    #[Test]
    #[DataProvider('provideUnreadableConfirmations')]
    public function aConfirmationThatNamesNothingIsRefused(mixed $cnf, string $description): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($description);

        // When
        Confirmations::fromClaims([
            'cnf' => $cnf,
        ]);
    }

    /**
     * A token is bound to one thing: a "cnf" naming two is not one this provider wrote, and honouring
     * whichever member came first would be the provider choosing what the token means.
     */
    #[Test]
    public function aConfirmationOfTwoKindsAtOnceIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('bound to one thing');

        // When
        Confirmations::fromMembers([
            'x5t#S256' => self::THUMBPRINT,
            'jkt' => self::THUMBPRINT,
        ]);
    }

    /**
     * Two confirmations name the same thing when they are of the same kind and carry the same
     * thumbprint; the same thumbprint under another member names another thing.
     */
    #[Test]
    #[DataProvider('provideComparisons')]
    public function itMatchesWhatNamesTheSameThing(ConfirmationInterface $one, ConfirmationInterface $other, bool $same): void
    {
        // When / Then
        static::assertSame($same, $one->matches($other));
    }

    /**
     * @return iterable<string, array{ConfirmationInterface}>
     */
    public static function provideConfirmations(): iterable
    {
        yield 'a certificate' => [CertificateConfirmation::ofCertificate(Certificates::client())];
        yield 'a key' => [new KeyConfirmation(self::THUMBPRINT)];
    }

    /**
     * @return iterable<string, array{ConfirmationInterface, ConfirmationInterface, bool}>
     */
    public static function provideComparisons(): iterable
    {
        yield 'the same key' => [new KeyConfirmation(self::THUMBPRINT), new KeyConfirmation(self::THUMBPRINT), true];
        yield 'another key' => [new KeyConfirmation(self::THUMBPRINT), new KeyConfirmation('5bPRpDFfR6QNNOFrxJLPHlbCcFEHFwWVtOJQCg8h2hM'), false];
        yield 'the same certificate' => [CertificateConfirmation::ofCertificate(Certificates::client()), CertificateConfirmation::ofCertificate(Certificates::client()), true];
        yield 'another certificate' => [CertificateConfirmation::ofCertificate(Certificates::client()), CertificateConfirmation::ofCertificate(Certificates::other()), false];
        yield 'the same thumbprint of another kind' => [new KeyConfirmation(self::THUMBPRINT), new CertificateConfirmation(self::THUMBPRINT), false];
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function provideUnreadableConfirmations(): iterable
    {
        yield 'a thumbprint that is not a string' => [[
            'x5t#S256' => 42,
        ], 'carries a thumbprint'];

        yield 'an empty thumbprint' => [[
            'x5t#S256' => '',
        ], 'names the certificate'];

        yield 'a key thumbprint of the wrong shape' => [[
            'jkt' => 'a-key-thumbprint',
        ], 'JWK thumbprint'];

        yield 'a member this provider does not write' => [[
            'kid' => 'the-key',
        ], 'names one of'];

        yield 'a confirmation that is not an object' => ['x5t#S256', 'names one of'];
    }
}
