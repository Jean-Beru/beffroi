<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Certificate;

use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * What the edge hands over, read into the leaf and its thumbprint: a PEM envelope carrying a certificate,
 * an empty envelope when the client presented none, and nothing else accepted.
 */
final class ClientCertificateTest extends TestCase
{
    /**
     * A certificate of no authority, self-signed on a P-256 key, the shape a client presents for
     * "self_signed_tls_client_auth" (RFC 8705 §2.2). Its thumbprint below is what "openssl x509 -outform
     * DER | openssl dgst -sha256" gives for it.
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
     * RFC 8705 §3.1: the thumbprint names the DER encoding of the certificate, not its PEM envelope.
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

    /**
     * The listener asks for a certificate without requiring one, so the envelope it fills is empty
     * whenever the client presented nothing: that is an answer, not a failure.
     */
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

    /**
     * A misconfigured edge is said out loud rather than guessed at: a provider that bound a token to
     * bytes nobody chose would bind it to nothing.
     */
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
