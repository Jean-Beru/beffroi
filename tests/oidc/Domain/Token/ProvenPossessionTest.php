<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Domain\Token\ProvenPossession;
use Heidi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What a request proved it holds, against what a token is bound to (RFC 8705 §3, RFC 9449 §7.1).
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

    /**
     * A bound token replayed by whoever proved nothing opens nothing.
     */
    #[Test]
    public function aRequestThatProvedNothingProvesNothing(): void
    {
        // When / Then
        static::assertFalse(ProvenPossession::none()->proves(new KeyConfirmation(self::THUMBPRINT)));
    }

    /**
     * A request made over a connection that carried a certificate and with a proof of a key proves both,
     * and a token bound to either one of them is honoured.
     */
    #[Test]
    public function aRequestMayProveMoreThanOneThing(): void
    {
        // Given
        $proven = ProvenPossession::of([CertificateConfirmation::ofCertificate(Certificates::client()), new KeyConfirmation(self::THUMBPRINT)]);

        // When / Then
        static::assertTrue($proven->proves(new KeyConfirmation(self::THUMBPRINT)));
    }

    /**
     * What proved nothing is left out, so that a caller hands over what each way of proving made of the
     * request without sorting it first.
     */
    #[Test]
    public function whatProvedNothingIsLeftOut(): void
    {
        // When
        $proven = ProvenPossession::of([null, new KeyConfirmation(self::THUMBPRINT), null]);

        // Then
        static::assertCount(1, $proven->proofs);
    }
}
