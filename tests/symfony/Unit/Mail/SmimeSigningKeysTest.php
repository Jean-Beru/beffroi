<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use App\Mail\SmimeCertificate;
use App\Mail\SmimeSigningKeys;
use App\Tests\Symfony\Fixture\MailFixtures;
use App\Tests\Symfony\Fixture\MailSigningKeys;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use DateTimeImmutable;
use function openssl_pkey_export;
use function openssl_pkey_get_private;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function is_string;
use LogicException;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 8551 §4.1, RFC 8550 §3, §4.4
 */
final class SmimeSigningKeysTest extends TestCase
{
    #[Test]
    public function aKeyAndItsCertificateAreSetForTheSenderTheCertificateNames(): void
    {
        // When
        $key = MailSigningKeys::smime(Fixtures::tenant());

        // Then
        static::assertSame('smime', $key->kind);
        static::assertSame(SmimeCertificate::of(MailFixtures::read('sender-certificate.pem'))->fingerprint(), $key->fingerprint);
        static::assertSame('2126-01-01', $key->notAfter?->format('Y-m-d'));
        static::assertCount(2, SmimeCertificate::blocksOf($key->published));
    }

    #[Test]
    public function thePrivateHalfIsSealedAndWrittenNowhereInClear(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // When
        $key = MailSigningKeys::smime($tenant);

        // Then
        static::assertStringNotContainsString('PRIVATE KEY', $key->published);
        static::assertSame('RSA', Keys::sealer()->unseal($tenant, $key->sealedPrivateJwk)['kty'] ?? null);
    }

    #[Test]
    #[DataProvider('provideKeysThatDoNotSign')]
    public function aKeyAndACertificateThatDoNotSignForTheSenderAreRefused(string $privateKey, string $certificates, string $because): void
    {
        // Given
        $keys = new SmimeSigningKeys(Keys::sealer(), new MockClock(new DateTimeImmutable('2026-11-22T10:00:00+00:00')));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($because);

        // When
        $keys->of(Fixtures::tenant(), $privateKey, $certificates, new EmailAddress(MailSigningKeys::SENDER));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideKeysThatDoNotSign(): iterable
    {
        $key = MailFixtures::read('sender-key.pem');
        $certificate = MailFixtures::read('sender-certificate.pem');
        $private = openssl_pkey_get_private($key);
        if ($private === false) {
            throw new LogicException('The fixture key does not open.');
        }
        openssl_pkey_export($private, $protected, 'a passphrase');
        yield 'no certificate' => [$key, '', 'The certificate of the key is given in PEM, first, before the chain above it.'];
        yield 'the certificate of another key' => [
            $key,
            MailFixtures::read('sender-next-certificate.pem'),
            'The certificate does not certify this key, or the key is an RSA key under 2048 bits.',
        ];
        yield 'a certificate that has expired' => [
            MailFixtures::read('sender-expired-key.pem'),
            MailFixtures::read('sender-expired-certificate.pem'),
            'The certificate is not valid now.',
        ];
        yield 'a certificate for another sender' => [
            MailFixtures::read('person-key.pem'),
            MailFixtures::read('person-certificate.pem'),
            'The certificate does not name the address this deployment writes its mail from.',
        ];
        yield 'a key protected by a passphrase' => [
            is_string($protected) ? $protected : '',
            $certificate,
            'This is not a private key in PEM, or it is protected by a passphrase.',
        ];
        yield 'a certificate where a key is expected' => [$certificate, $certificate, 'This is not a private key in PEM, or it is protected by a passphrase.'];
    }
}
