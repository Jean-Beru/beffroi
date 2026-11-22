<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\CertificateConfirmationKind;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Application\Token\Confirmations;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Token\KeyConfirmationKind;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Bindings;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7800 §3.1, RFC 8705 §3.1, RFC 9449 §6.1
 */
final class ConfirmationsTest extends TestCase
{
    /**
     * RFC 7638 §3.1
     */
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    /**
     * RFC 8705 §3.1
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
        static::assertSame(
            [
                'cnf' => [
                    'x5t#S256' => $certificate->x5tS256(),
                ],
            ],
            $confirmation->toClaims(),
        );
    }

    /**
     * RFC 9449 §6.1, §7.1
     */
    #[Test]
    public function aKeyIsNamedByItsJwkThumbprint(): void
    {
        // When
        $confirmation = new KeyConfirmation(self::THUMBPRINT);

        // Then
        static::assertSame(self::THUMBPRINT, $confirmation->value());
        static::assertSame('DPoP', $confirmation->scheme());
        static::assertSame(
            [
                'cnf' => [
                    'jkt' => self::THUMBPRINT,
                ],
            ],
            $confirmation->toClaims(),
        );
    }

    #[Test]
    #[DataProvider('provideConfirmations')]
    public function itReadsBackTheClaimItWrote(ConfirmationInterface $written): void
    {
        // When
        $read = Bindings::wired()->fromClaims($written->toClaims());

        // Then
        static::assertEquals($written, $read);
    }

    #[Test]
    public function claimsWithoutAConfirmationAreABearerToken(): void
    {
        // When
        $confirmation = Bindings::wired()->fromClaims([
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
        Bindings::wired()->fromClaims([
            'cnf' => $cnf,
        ]);
    }

    #[Test]
    public function aConfirmationOfTwoKindsAtOnceIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('bound to one thing');

        // When
        Bindings::wired()->fromMembers([
            'x5t#S256' => self::THUMBPRINT,
            'jkt' => self::THUMBPRINT,
        ]);
    }

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
        yield 'the same certificate' => [
            CertificateConfirmation::ofCertificate(Certificates::client()),
            CertificateConfirmation::ofCertificate(Certificates::client()),
            true,
        ];
        yield 'another certificate' => [
            CertificateConfirmation::ofCertificate(Certificates::client()),
            CertificateConfirmation::ofCertificate(Certificates::other()),
            false,
        ];
        yield 'the same thumbprint of another kind' => [new KeyConfirmation(self::THUMBPRINT), new CertificateConfirmation(self::THUMBPRINT), false];
    }

    #[Test]
    public function theSchemesAResourceServesAreThoseOfTheWiredBindings(): void
    {
        // When
        $schemes = Bindings::wired()->servedTokenSchemes();

        // Then
        static::assertSame([TokenResponse::BEARER, KeyConfirmation::SCHEME], $schemes);
    }

    #[Test]
    public function aDeploymentThatBindsToCertificatesAloneServesBearerTokensOnly(): void
    {
        // Given
        $confirmations = new Confirmations([new CertificateConfirmationKind()]);

        // When
        $schemes = $confirmations->servedTokenSchemes();

        // Then
        static::assertSame([TokenResponse::BEARER], $schemes);
    }

    #[Test]
    public function twoKindsAnsweringForOneMemberAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Two confirmation kinds answer for the "jkt" member of a "cnf".');

        // When
        new Confirmations([new KeyConfirmationKind(), new KeyConfirmationKind()]);
    }

    #[Test]
    public function aProviderThatBindsNothingIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider binds its tokens with at least one kind of confirmation.');

        // When
        new Confirmations([]);
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function provideUnreadableConfirmations(): iterable
    {
        yield 'a thumbprint that is not a string' => [
            [
                'x5t#S256' => 42,
            ],
            'carries a thumbprint',
        ];

        yield 'an empty thumbprint' => [
            [
                'x5t#S256' => '',
            ],
            'names the certificate',
        ];

        yield 'a key thumbprint of the wrong shape' => [
            [
                'jkt' => 'a-key-thumbprint',
            ],
            'JWK thumbprint',
        ];

        yield 'a member this provider does not write' => [
            [
                'kid' => 'the-key',
            ],
            'names one of',
        ];

        yield 'a confirmation that is not an object' => ['x5t#S256', 'names one of'];
    }

    /**
     * RFC 7800 §3.1
     *
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideMembers')]
    public function aConfirmationWritesTheMembersAColumnHoldsItAs(ConfirmationInterface $confirmation, array $members): void
    {
        // When / Then
        static::assertSame($members, $confirmation->toMembers());
    }

    /**
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideMembers')]
    public function aConfirmationComesBackOutOfItsMembers(ConfirmationInterface $confirmation, array $members): void
    {
        // When / Then
        static::assertEquals($confirmation, self::confirmations()->fromMembers($members));
    }

    /**
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideMembers')]
    public function theClaimOfATokenCarriesThoseSameMembers(ConfirmationInterface $confirmation, array $members): void
    {
        // When / Then
        static::assertSame(
            [
                ConfirmationInterface::CLAIM => $members,
            ],
            $confirmation->toClaims(),
        );
    }

    /**
     * @return iterable<string, array{ConfirmationInterface, array<string, mixed>}>
     */
    public static function provideMembers(): iterable
    {
        yield 'a key the client proved possession of' => [
            new KeyConfirmation(self::THUMBPRINT),
            [
                'jkt' => self::THUMBPRINT,
            ],
        ];
        yield 'the certificate the client presented' => [
            new CertificateConfirmation(self::THUMBPRINT),
            [
                'x5t#S256' => self::THUMBPRINT,
            ],
        ];
    }

    private static function confirmations(): Confirmations
    {
        return new Confirmations([new KeyConfirmationKind(), new CertificateConfirmationKind()]);
    }
}
