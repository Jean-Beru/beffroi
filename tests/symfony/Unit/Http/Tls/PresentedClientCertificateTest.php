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
 * RFC 8705 §2, RFC 6749 §5.2
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

    #[Test]
    public function aRequestMadeWithoutACertificateCarriesNone(): void
    {
        // When
        $certificate = $this->certificates->ofRequest(new Request());

        // Then
        static::assertNull($certificate);
    }

    /**
     * Decision 0006, RFC 6749 §5.2
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
