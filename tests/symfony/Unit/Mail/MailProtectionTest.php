<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use App\Mail\PgpMailSigner;
use App\Mail\Smime;
use App\Mail\SmimeMailSigner;
use App\Tests\Symfony\Fixture\MailFixtures;
use App\Tests\Symfony\Fixture\MailProtections;
use App\Tests\Symfony\Fixture\MailSigningKeys;
use App\Tests\Symfony\Fixture\ScratchFiles;
use Beffroi\Saml\Tests\Fixture\RecordingLogger;
use Beffroi\Core\Bridge\InMemory\InMemoryMailSigningKeyRepository;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use function openssl_pkcs7_decrypt;
use function openssl_pkcs7_verify;
use function openssl_x509_fingerprint;
use const PKCS7_DETACHED;
use const PKCS7_NOVERIFY;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Message;

/**
 * Decision 0051, RFC 8551 §3.7, RFC 3156 §6.1
 */
final class MailProtectionTest extends TestCase
{
    private const string NOW = '2026-11-22T10:00:00+00:00';

    private Tenant $tenant;

    private InMemoryMailSigningKeyRepository $keys;

    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryMailSigningKeyRepository();
    }

    #[Test]
    public function aTenantThatHoldsNoKeyWritesTheMailAsItIs(): void
    {
        // Given
        $mail = self::mail();

        // When
        $protected = $this->protect($this->person(), $mail);

        // Then
        static::assertSame($mail, $protected);
    }

    #[Test]
    public function theCurrentKeySignsTheMail(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // When
        $protected = $this->protect($this->person(), self::mail());

        // Then
        static::assertSame('sender', self::signerOf($protected));
    }

    #[Test]
    public function theKeySetInPlaceOfAnotherSignsAndTheOneItReplacedNoLonger(): void
    {
        // Given
        $replaced = MailSigningKeys::smime($this->tenant, 'sender', new DateTimeImmutable('2026-11-01T10:00:00+00:00'));
        $replaced->replace(new DateTimeImmutable('2026-11-20T10:00:00+00:00'));
        $this->keys->save($replaced);
        $this->keys->save(MailSigningKeys::smime($this->tenant, 'sender-next', new DateTimeImmutable('2026-11-20T10:00:00+00:00')));

        // When
        $protected = $this->protect($this->person(), self::mail());

        // Then
        static::assertSame('sender-next', self::signerOf($protected));
    }

    #[Test]
    public function aKeyPastItsCertificateLeavesTheMailUnwritten(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // When
        $protected = $this->protect($this->person(), self::mail(), '2126-06-01T00:00:00+00:00');

        // Then
        static::assertNull($protected);
        static::assertSame('error', $this->logger->records[0]['level'] ?? null);
    }

    #[Test]
    public function aKeySetForAnotherSenderLeavesTheMailUnwritten(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // When
        $protected = $this->protect($this->person(), self::mail(), sender: 'alerts@acme.example');

        // Then
        static::assertNull($protected);
    }

    #[Test]
    public function withoutAKeyOfTheFormatOfThePersonTheFirstFormatWiredSigns(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $this->keys->save(MailSigningKeys::pgp($this->tenant));

        // When
        $protected = $this->protect($this->person(), self::mail());

        // Then
        static::assertStringContainsString('protocol="application/pkcs7-signature"', (string) $protected?->toString());
    }

    #[Test]
    public function theFormatOfTheKeyThePersonGaveSignsTheMailToThem(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $this->keys->save(MailSigningKeys::pgp($this->tenant));
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));
        $clock = new MockClock(self::NOW);

        // When
        $protected = MailProtections::over($this->keys, $clock, signers: [
            new PgpMailSigner($clock),
            new SmimeMailSigner(),
        ])->of($person, new EmailAddress(MailSigningKeys::SENDER), self::mail());

        // Then
        static::assertStringContainsString('protocol="application/pkcs7-signature"', self::decrypted((string) $protected?->toString()));
    }

    #[Test]
    public function aMailToAPersonWhoGaveACertificateIsSignedThenEncrypted(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));

        // When
        $protected = (string) $this->protect($person, self::mail())?->toString();

        // Then
        static::assertStringContainsString('application/pkcs7-mime', $protected);
        static::assertStringNotContainsString('Open your account to answer.', $protected);
        static::assertStringContainsString('multipart/signed', self::decrypted($protected));
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    public function theConfirmationOfAnAddressIsSignedAndEncryptedToNoOne(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));

        // When
        $protected = (string) MailProtections::over($this->keys, new MockClock(self::NOW), $this->logger)
            ->ofAConfirmation($person, new EmailAddress(MailSigningKeys::SENDER), self::mail())
            ?->toString();

        // Then
        static::assertStringContainsString('protocol="application/pkcs7-signature"', $protected);
        static::assertStringNotContainsString('application/pkcs7-mime', $protected);
        static::assertSame('sender', self::signerOf(MailProtections::over($this->keys, new MockClock(self::NOW), $this->logger)->ofAConfirmation($person, new EmailAddress(MailSigningKeys::SENDER), self::mail())));
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    public function theConfirmationOfATenantThatSignsAndCannotSignItIsWrittenToNobody(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // When
        $protected = MailProtections::over($this->keys, new MockClock(self::NOW), $this->logger)
            ->ofAConfirmation($this->person(), new EmailAddress('someone-else@acme.example'), self::mail());

        // Then
        static::assertNull($protected);
    }

    #[Test]
    public function aPersonWhoseCertificateIsNoLongerValidIsWrittenNothing(): void
    {
        // Given
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));

        // When
        $protected = $this->protect($person, self::mail(), '2126-06-01T00:00:00+00:00');

        // Then
        static::assertNull($protected);
        static::assertSame('warning', $this->logger->records[0]['level'] ?? null);
    }

    #[Test]
    public function aPersonWhoseKeyNoWiredFormatWritesIsWrittenNothing(): void
    {
        // Given
        $person = $this->person();
        $person->encryptMailTo(new MailEncryptionKey(
            'elsewhere',
            'material',
            'ABCD',
            [new EmailAddress('alice@acme.example')],
        ), new DateTimeImmutable(self::NOW));

        // When
        $protected = $this->protect($person, self::mail());

        // Then
        static::assertNull($protected);
    }

    private function protect(User $user, Email $mail, string $now = self::NOW, string $sender = MailSigningKeys::SENDER): ?Message
    {
        return MailProtections::over($this->keys, new MockClock($now), $this->logger)->of($user, new EmailAddress($sender), $mail);
    }

    private function person(): User
    {
        $user = Fixtures::user($this->tenant);
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, new DateTimeImmutable(self::NOW));

        return $user;
    }

    private static function mail(): Email
    {
        return new Email()
            ->from(MailSigningKeys::SENDER)
            ->to('alice@acme.example')
            ->subject('A sign-in is waiting')
            ->text('Open your account to answer.');
    }

    /**
     * The name of the fixture whose certificate signed it.
     */
    private static function signerOf(?Message $message): string
    {
        $files = new ScratchFiles();
        $signer = $files->holding();
        openssl_pkcs7_verify($files->holding((string) $message?->toString()), PKCS7_DETACHED | PKCS7_NOVERIFY, $signer);
        $certificate = ScratchFiles::read($signer);
        foreach (['sender', 'sender-next'] as $name) {
            if (openssl_x509_fingerprint($certificate, 'sha256') === openssl_x509_fingerprint(MailFixtures::read($name . '-certificate.pem'), 'sha256')) {
                return $name;
            }
        }

        return 'nobody';
    }

    private static function decrypted(string $message): string
    {
        $files = new ScratchFiles();
        $opened = $files->holding();
        openssl_pkcs7_decrypt($files->holding($message), $opened, MailFixtures::read('person-certificate.pem'), MailFixtures::read('person-key.pem'));

        return ScratchFiles::read($opened);
    }
}
