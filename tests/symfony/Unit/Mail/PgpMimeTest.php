<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use App\Mail\Gnupg;
use App\Mail\PgpMime;
use App\Tests\Symfony\Fixture\MailFixtures;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionRefusal;
use Beffroi\Core\Exception\MailEncryptionRefusedException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Mime\Email;
use Symfony\Component\Process\Process;
use function bin2hex;
use function mkdir;
use function random_bytes;
use function strpos;
use function substr;
use function sys_get_temp_dir;

/**
 * RFC 3156, RFC 9580. gpg reads and encrypts: on a machine that carries none, the tests that need it are skipped.
 */
final class PgpMimeTest extends TestCase
{
    #[Test]
    public function aKeyIsReadWithTheAddressOfItsUserIdAndItsFingerprint(): void
    {
        // When
        $key = $this->pgp()->read(MailFixtures::read('alice-public.asc'));

        // Then
        static::assertSame('pgp', $key->kind);
        static::assertSame('613A147A0FF6389681749A6D032D686EC949BDC4', $key->fingerprint);
        static::assertTrue($key->binds(new EmailAddress('alice@acme.example')));
        static::assertNull($key->notAfter);
    }

    #[Test]
    #[DataProvider('provideWhatIsNoKeyAMailIsEncryptedTo')]
    public function whatIsNoKeyAMailIsEncryptedToIsRefused(string $material, MailEncryptionRefusal $refusal): void
    {
        // When
        try {
            $this->pgp()->read($material);
            static::fail('The key was read.');
        } catch (MailEncryptionRefusedException $exception) {
            // Then
            static::assertSame($refusal, $exception->refusal);
        }
    }

    /**
     * @return iterable<string, array{string, MailEncryptionRefusal}>
     */
    public static function provideWhatIsNoKeyAMailIsEncryptedTo(): iterable
    {
        yield 'nothing' => ['', MailEncryptionRefusal::Unreadable];
        yield 'two keys' => [MailFixtures::read('two-keys-public.asc'), MailEncryptionRefusal::Unreadable];
        yield 'a secret key' => [MailFixtures::read('alice-secret.asc'), MailEncryptionRefusal::Unreadable];
        yield 'more than it could be' => [MailFixtures::read('alice-public.asc') . str_repeat(' ', PgpMime::LONGEST), MailEncryptionRefusal::Unreadable];
        yield 'a block that is no key' => [
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
            MailEncryptionRefusal::Unreadable,
        ];
        yield 'a key that only signs' => [MailFixtures::read('carol-sign-only-public.asc'), MailEncryptionRefusal::NotForEncryption];
        yield 'a revoked key' => [MailFixtures::read('dave-revoked-public.asc'), MailEncryptionRefusal::NotValidNow];
        yield 'an expired key' => [MailFixtures::read('erin-expired-public.asc'), MailEncryptionRefusal::NotValidNow];
    }

    /**
     * RFC 3156 §4, RFC 9580 §5.1: the session key is encrypted to the encryption subkey of that key, and to no other.
     */
    #[Test]
    public function theMailIsEncryptedToTheSubkeyOfTheKey(): void
    {
        // Given
        $pgp = $this->pgp();
        $key = $pgp->read(MailFixtures::read('alice-public.asc'));
        $mail = new Email()
            ->from('no-reply@acme.example')
            ->to('alice@acme.example')
            ->subject('A sign-in is waiting')
            ->text('Open your account to answer.');

        // When
        $encrypted = $pgp->encrypt($mail, $key)->toString();

        // Then
        static::assertStringContainsString('multipart/encrypted; protocol="application/pgp-encrypted"', $encrypted);
        static::assertStringNotContainsString('Open your account to answer.', $encrypted);
        static::assertStringContainsString('keyid 2C752F71132E7413', self::packets($encrypted));
    }

    private function pgp(): PgpMime
    {
        $gpg = MailFixtures::gpg();
        if ($gpg === null) {
            static::markTestSkipped('gpg is not installed here.');
        }

        return new PgpMime(new Gnupg($gpg));
    }

    private static function packets(string $message): string
    {
        $start = (int) strpos($message, '-----BEGIN PGP MESSAGE-----');
        $end = (int) strpos($message, '-----END PGP MESSAGE-----') + 25;
        $home = sys_get_temp_dir() . '/pgp-test-' . bin2hex(random_bytes(4));
        mkdir($home, 0o700);
        $listing = new Process(['gpg', '--batch', '--list-packets'], null, ['GNUPGHOME' => $home], substr($message, $start, $end - $start));
        $listing->run();
        new Process(['rm', '-rf', $home])->run();

        return $listing->getOutput() . $listing->getErrorOutput();
    }
}
