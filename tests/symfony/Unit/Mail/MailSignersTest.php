<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use App\Mail\PgpMailSigner;
use App\Mail\SmimeMailSigner;
use App\Tests\Symfony\Fixture\MailFixtures;
use App\Tests\Symfony\Fixture\MailSigningKeys;
use App\Tests\Symfony\Fixture\ScratchFiles;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use function openssl_pkcs7_verify;
use function openssl_x509_fingerprint;
use const PKCS7_DETACHED;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Part\AbstractMultipartPart;

/**
 * RFC 8551 §3.5.3, RFC 3156 §5, RFC 1847 §2.1: both signatures are detached, the content first and the signature
 * second in a multipart/signed.
 */
final class MailSignersTest extends TestCase
{
    #[Test]
    public function anSmimeSignatureIsAMultipartSignedWithAPkcs7SignaturePart(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = MailSigningKeys::smime($tenant);

        // When
        $signed = new SmimeMailSigner()
            ->sign(self::mail(), $key, Keys::sealer()->unseal($tenant, $key->sealedPrivateJwk))
            ->toString();

        // Then
        static::assertMatchesRegularExpression('/Content-Type: multipart\/signed; protocol="application\/pkcs7-signature";\s+micalg=sha-256/', $signed);
        static::assertStringContainsString('Content-Type: application/pkcs7-signature; name="smime.p7s"', $signed);
        static::assertStringNotContainsString('application/pkcs7-mime', $signed);
    }

    #[Test]
    public function anSmimeSignatureVerifiesUnderTheCertificateAuthorityOfItsChain(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = MailSigningKeys::smime($tenant);
        $signed = new SmimeMailSigner()
            ->sign(self::mail(), $key, Keys::sealer()->unseal($tenant, $key->sealedPrivateJwk))
            ->toString();
        $files = new ScratchFiles();
        $signer = $files->holding();

        // When
        $verified = openssl_pkcs7_verify($files->holding($signed), PKCS7_DETACHED, $signer, [$files->holding(MailFixtures::read('ca-certificate.pem'))]);

        // Then
        $signerCertificate = ScratchFiles::read($signer);
        static::assertTrue($verified);
        static::assertSame(
            (string) openssl_x509_fingerprint(MailFixtures::read('sender-certificate.pem'), 'sha256'),
            (string) openssl_x509_fingerprint($signerCertificate, 'sha256'),
        );
    }

    #[Test]
    public function aPgpSignatureIsAMultipartSignedWithAPgpSignaturePartOverTheBodyAsItIsSent(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = MailSigningKeys::pgp($tenant);
        $mail = self::mail();

        // When
        $signed = new PgpMailSigner(new MockClock())->sign($mail, $key, Keys::sealer()->unseal($tenant, $key->sealedPrivateJwk));

        // Then
        $body = $signed->getBody();
        static::assertInstanceOf(AbstractMultipartPart::class, $body);
        static::assertMatchesRegularExpression('/multipart\/signed;\s+micalg=pgp-sha256;\s+protocol="application\/pgp-signature"/', $signed->toString());
        static::assertSame($mail->getBody()->toString(), $body->getParts()[0]->toString());
        static::assertStringStartsWith('-----BEGIN PGP SIGNATURE-----', $body->getParts()[1]->bodyToString());
    }

    private static function mail(): Email
    {
        return new Email()
            ->from(MailSigningKeys::SENDER)
            ->to('alice@acme.example')
            ->subject('A sign-in is waiting')
            ->text("Open your account to answer.\nAcme");
    }
}
