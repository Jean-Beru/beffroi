<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Certificate;

use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

final class ClientCertificateTest extends TestCase
{
    /**
     * RFC 8705 §2.2
     */
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

    /**
     * RFC 8705 §3.1
     */
    #[Test]
    public function itComputesTheThumbprintOfTheDerEncoding(): void
    {
        // Given
        $certificate = ClientCertificate::fromPem(self::PEM);

        // Then
        static::assertNotNull($certificate);
        static::assertSame(523, strlen($certificate->der));
        static::assertSame(self::X5T_S256, $certificate->x5tS256());
    }

    #[Test]
    #[DataProvider('provideEmptyEnvelopes')]
    public function anEmptyEnvelopeIsNoCertificate(string $pem): void
    {
        // When
        $certificate = ClientCertificate::fromPem($pem);

        // Then
        static::assertNull($certificate);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEmptyEnvelopes(): iterable
    {
        yield 'what Caddy writes when no certificate was presented' => ["-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"];

        yield 'an envelope holding nothing but whitespace' => ["-----BEGIN CERTIFICATE-----\n   \n\t\n-----END CERTIFICATE-----\n"];
    }

    #[Test]
    public function itRefusesWhatIsNotAPemEnvelope(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The edge handed over 20 bytes that are not a PEM certificate envelope.');

        // When
        ClientCertificate::fromPem('MIICBzCCAaygAwIBAgI=');
    }

    #[Test]
    public function itRefusesAnEnvelopeThatIsNotBase64(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The edge handed over a PEM certificate envelope whose contents are not base64.');

        // When
        ClientCertificate::fromPem("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n");
    }
}
