<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http\Tls;

use App\Http\Tls\EdgeClientCertificateResolver;
use App\Http\Tls\ForgedClientCertificateException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;

/**
 * Decision 0006
 */
final class EdgeClientCertificateResolverTest extends TestCase
{
    private const string PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICBzCCAaygAwIBAgIBATAKBggqhkjOPQQDAjBhMRowGAYDVQQDDBFoZWlkaS10
        ZXN0LWNsaWVudDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf
        BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yNjA5MjExNjQzMDNa
        GA8yMTI2MDgyODE2NDMwM1owYTEaMBgGA1UEAwwRaGVpZGktdGVzdC1jbGllbnQx
        CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
        cm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARA
        x9ThBfX1wyp3wuvRrgCHO8a0enxJwhjOY0vSkSs09NKXD1HYY03ubpw3cSaRtMGv
        r75fCrxmxFluJCHZPOZFo1MwUTAdBgNVHQ4EFgQULKjfsYmYCfCVl9Yi4YuEtpfj
        zlUwHwYDVR0jBBgwFoAULKjfsYmYCfCVl9Yi4YuEtpfjzlUwDwYDVR0TAQH/BAUw
        AwEB/zAKBggqhkjOPQQDAgNJADBGAiEArjz+EWOcrZzQ05nDpyR3UN/S9hVxtnrM
        Wzy3QoPxNqECIQCRbCjIl47tdhUwGzQcb/M0ADuBuLU88sBvMqtUWWfrJw==
        -----END CERTIFICATE-----
        PEM;

    private const string X5T_S256 = 'kPiIukPNPlPrfFHgFmC5C23td-On7wYZ8lVaLFBT8h8';

    #[Test]
    public function itReadsTheCertificateTheListenerHandedOver(): void
    {
        // Given
        $request = Request::create('/', server: [
            EdgeClientCertificateResolver::VARIABLE => self::PEM,
        ]);

        // When
        $certificate = new EdgeClientCertificateResolver()->ofRequest($request);

        // Then
        static::assertSame(self::X5T_S256, $certificate?->x5tS256());
    }

    #[Test]
    #[DataProvider('provideRequestsWithoutACertificate')]
    public function aRequestMadeWithoutACertificateHasNone(string $variable): void
    {
        // Given
        $request = Request::create(
            '/',
            server: $variable === ''
                ? []
                : [
                    EdgeClientCertificateResolver::VARIABLE => $variable,
                ],
        );

        // When
        $certificate = new EdgeClientCertificateResolver()->ofRequest($request);

        // Then
        static::assertNull($certificate);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRequestsWithoutACertificate(): iterable
    {
        yield 'a host whose listener sets the variable nowhere' => [''];

        yield 'a listener that asked and was presented nothing' => ["-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"];
    }

    /**
     * Decision 0006
     */
    #[Test]
    #[DataProvider('provideRefusedHeaders')]
    public function itRefusesACertificateCarriedInAHeader(string $header): void
    {
        // Given
        $request = Request::create('/', server: [
            'HTTP_' . strtoupper(strtr($header, '-', '_')) => self::PEM,
        ]);

        // Then
        $this->expectException(ForgedClientCertificateException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The request carries a client certificate in the "%s" header, which nothing in front of this application sets.',
            $header,
        ));

        // When
        new EdgeClientCertificateResolver()->ofRequest($request);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedHeaders(): iterable
    {
        foreach (EdgeClientCertificateResolver::REFUSED_HEADERS as $header) {
            yield $header => [$header];
        }
    }

    #[Test]
    public function aForgedHeaderIsRefusedEvenBesideARealCertificate(): void
    {
        // Given
        $request = Request::create('/', server: [
            EdgeClientCertificateResolver::VARIABLE => self::PEM,
            'HTTP_X_CLIENT_CERT' => self::PEM,
        ]);

        // Then
        $this->expectException(ForgedClientCertificateException::class);

        // When
        new EdgeClientCertificateResolver()->ofRequest($request);
    }
}
