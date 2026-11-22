<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use App\Mail\Smime;
use App\Tests\Symfony\Fixture\MailFixtures;
use App\Tests\Symfony\Fixture\ScratchFiles;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionRefusal;
use Beffroi\Core\Exception\MailEncryptionRefusedException;
use function openssl_pkcs7_decrypt;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Mime\Email;

/**
 * RFC 8551, RFC 8550
 */
final class SmimeTest extends TestCase
{
    #[Test]
    public function aCertificateIsReadWithTheAddressItNamesAndItsDates(): void
    {
        // When
        $key = new Smime()->read(MailFixtures::read('person-certificate.pem'));

        // Then
        static::assertSame('smime', $key->kind);
        static::assertTrue($key->binds(new EmailAddress('alice@acme.example')));
        static::assertSame('2020-01-01', $key->notBefore?->format('Y-m-d'));
        static::assertSame('2126-01-01', $key->notAfter?->format('Y-m-d'));
        static::assertMatchesRegularExpression('/^[0-9A-F]{64}$/', $key->fingerprint);
    }

    #[Test]
    #[DataProvider('provideWhatIsNoCertificateAMailIsEncryptedTo')]
    public function whatIsNoCertificateAMailIsEncryptedToIsRefused(string $material, MailEncryptionRefusal $refusal): void
    {
        // When
        try {
            new Smime()->read($material);
            static::fail('The certificate was read.');
        } catch (MailEncryptionRefusedException $exception) {
            // Then
            static::assertSame($refusal, $exception->refusal);
        }
    }

    /**
     * @return iterable<string, array{string, MailEncryptionRefusal}>
     */
    public static function provideWhatIsNoCertificateAMailIsEncryptedTo(): iterable
    {
        $certificate = MailFixtures::read('person-certificate.pem');
        yield 'nothing' => ['', MailEncryptionRefusal::Unreadable];
        yield 'two certificates' => [$certificate . MailFixtures::read('ca-certificate.pem'), MailEncryptionRefusal::Unreadable];
        yield 'a block that is no certificate' => ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", MailEncryptionRefusal::Unreadable];
        yield 'more than it could be' => [$certificate . str_repeat(' ', Smime::LONGEST), MailEncryptionRefusal::Unreadable];
        yield 'an elliptic curve key, which PKCS #7 does not encrypt to' => [
            MailFixtures::read('person-ec-certificate.pem'),
            MailEncryptionRefusal::NotForEncryption,
        ];
        yield 'an RSA key of 1024 bits' => [MailFixtures::read('person-weak-certificate.pem'), MailEncryptionRefusal::NotForEncryption];
        yield 'a key for a server' => [MailFixtures::read('person-server-certificate.pem'), MailEncryptionRefusal::NotForEncryption];
    }

    /**
     * RFC 8551 §3.3
     */
    #[Test]
    public function theMailIsEnvelopedForTheCertificate(): void
    {
        // Given
        $smime = new Smime();
        $key = $smime->read(MailFixtures::read('person-certificate.pem'));
        $mail = new Email()
            ->from('no-reply@acme.example')
            ->to('alice@acme.example')
            ->subject('A sign-in is waiting')
            ->text('Open your account to answer.');

        // When
        $encrypted = $smime->encrypt($mail, $key);

        // Then
        $files = new ScratchFiles();
        $opened = $files->holding();
        static::assertStringContainsString('application/pkcs7-mime', $encrypted->toString());
        static::assertTrue(openssl_pkcs7_decrypt(
            $files->holding($encrypted->toString()),
            $opened,
            MailFixtures::read('person-certificate.pem'),
            MailFixtures::read('person-key.pem'),
        ));
        static::assertStringContainsString('Open your account to answer.', ScratchFiles::read($opened));
    }
}
