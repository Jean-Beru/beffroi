<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http\Tls;

use App\Http\Tls\EdgeClientCertificateResolver;
use App\Http\Tls\PresentedClientCertificate;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * What the protocol endpoints make of the certificate of a request (RFC 8705 §2): the one the edge
 * proved, or an error of RFC 6749 §5.2 when the request tried to bring one of its own.
 */
final class PresentedClientCertificateTest extends TestCase
{
    private PresentedClientCertificate $certificates;

    protected function setUp(): void
    {
        $this->certificates = new PresentedClientCertificate(new EdgeClientCertificateResolver());
    }

    #[Test]
    public function itReadsTheCertificateTheEdgeProved(): void
    {
        // Given
        $request = new Request(server: [
            EdgeClientCertificateResolver::VARIABLE => Certificates::pemOf(Certificates::client()),
        ]);

        // When
        $certificate = $this->certificates->ofRequest($request);

        // Then
        static::assertSame(Certificates::client()->x5tS256(), $certificate?->x5tS256());
    }

    /**
     * The listener asks for a certificate without requiring one: a request made without one is an
     * ordinary request, and the client authenticates some other way or not at all.
     */
    #[Test]
    public function aRequestMadeWithoutACertificateCarriesNone(): void
    {
        // When
        $certificate = $this->certificates->ofRequest(new Request());

        // Then
        static::assertNull($certificate);
    }

    /**
     * Decision 0006: a certificate in a header is somebody trying, and the endpoint says so with the
     * error of RFC 6749 §5.2 rather than serving the request without it. Which header it was is in the
     * logs, not in the answer: a description is a sentence of the provider and never one the request
     * chose (RFC 6749 §5.2).
     */
    #[Test]
    public function aCertificateCarriedInAHeaderIsAnInvalidRequest(): void
    {
        // Given
        $request = new Request(server: [
            'HTTP_X_FORWARDED_CLIENT_CERT' => Certificates::pemOf(Certificates::client()),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The request carries a client certificate in a header, which nothing in front of this provider sets.');

        // When
        $this->certificates->ofRequest($request);
    }

    /**
     * An edge that hands over something that is not a certificate is misconfigured, and the request is
     * refused rather than read as one made without a certificate.
     */
    #[Test]
    public function whatTheEdgeCouldNotHandOverIsAnInvalidRequest(): void
    {
        // Given
        $request = new Request(server: [
            EdgeClientCertificateResolver::VARIABLE => 'MIICBzCCAaygAwIBAgI=',
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The client certificate of this request could not be read.');

        // When
        $this->certificates->ofRequest($request);
    }
}
