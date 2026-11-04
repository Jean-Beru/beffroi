<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Token\ProvenPossession;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §3, RFC 9449 §7.1
 */
final class ProvenPossessionTest extends TestCase
{
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    #[Test]
    public function aRequestProvesWhatItPresentedAgain(): void
    {
        // Given
        $proven = ProvenPossession::of([CertificateConfirmation::ofCertificate(Certificates::client())]);

        // When / Then
        static::assertTrue($proven->proves(CertificateConfirmation::ofCertificate(Certificates::client())));
    }

    #[Test]
    public function aRequestProvesNothingItDidNotPresent(): void
    {
        // Given
        $proven = ProvenPossession::of([CertificateConfirmation::ofCertificate(Certificates::other())]);

        // When / Then
        static::assertFalse($proven->proves(CertificateConfirmation::ofCertificate(Certificates::client())));
    }

    #[Test]
    public function aRequestThatProvedNothingProvesNothing(): void
    {
        // When / Then
        static::assertFalse(ProvenPossession::none()->proves(new KeyConfirmation(self::THUMBPRINT)));
    }

    #[Test]
    public function aRequestMayProveMoreThanOneThing(): void
    {
        // Given
        $proven = ProvenPossession::of([CertificateConfirmation::ofCertificate(Certificates::client()), new KeyConfirmation(self::THUMBPRINT)]);

        // When / Then
        static::assertTrue($proven->proves(new KeyConfirmation(self::THUMBPRINT)));
    }

    #[Test]
    public function whatProvedNothingIsLeftOut(): void
    {
        // When
        $proven = ProvenPossession::of([null, new KeyConfirmation(self::THUMBPRINT), null]);

        // Then
        static::assertCount(1, $proven->proofs);
    }
}
