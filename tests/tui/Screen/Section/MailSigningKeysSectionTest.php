<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use function chmod;
use function count;
use function explode;
use function file_put_contents;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function rmdir;
use function sprintf;
use function str_contains;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * Decision 0051: the administrator of the tenant sets the keys its mail is signed with through the administration API,
 * an OpenPGP key the provider draws or an S/MIME key with its certificate and its chain, and removes one; each change is
 * an act that names the administrator.
 */
final class MailSigningKeysSectionTest extends TestCase
{
    private const string PGP = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678';

    private const string REPLACED = '0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C';

    private const string SMIME = '9B8A7C6D5E4F30211203F4E5D6C7B8A99B8A7C6D5E4F30211203F4E5D6C7B8A9';

    private const string KEY = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";

    private const string CHAIN = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";

    private ?SignedInScreen $screen = null;

    private ?string $directory = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
        if ($this->directory !== null) {
            unlink($this->directory . '/mail.key');
            unlink($this->directory . '/mail.crt');
            rmdir($this->directory);
        }
    }

    #[Test]
    public function eachKeySaysByAMarkAndAWordWhetherItSigns(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/tenant/mail-signing-keys' => self::tenantKeys()]);

        // When
        $this->screen->open('section.mail_signing_keys');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 1], [
            preg_match('/■ current +OpenPGP +A1B2/', $screen),
            preg_match('/▨ replaced +OpenPGP +0F1E/', $screen),
        ]);
    }

    #[Test]
    public function aTenantWithoutAKeyIsSaidToSendItsMailUnsigned(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/tenant/mail-signing-keys' => ['keys' => []]]);

        // When
        $this->screen->open('section.mail_signing_keys');

        // Then
        static::assertStringContainsString('No mail signing key: mail leaves unsigned.', $this->screen->screen());
    }

    /**
     * Drawing a key replaces the current one of its format, which then signs nothing: it is asked first.
     */
    #[Test]
    public function drawingAnOpenPgpKeyIsAskedToBeConfirmedFirst(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/tenant/mail-signing-keys' => self::tenantKeys()]);
        $this->screen->open('section.mail_signing_keys');

        // When
        $this->screen->press(["\r", 'p']);

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/tenant/mail-signing-keys/pgp', 'POST'),
            str_contains($this->screen->screen(), 'Generate an OpenPGP key? It replaces the key'),
        ]);
    }

    #[Test]
    public function anOpenPgpKeyIsDrawnOnceConfirmedAndWhereItIsServedIsSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/tenant/mail-signing-keys' => self::tenantKeys(),
            'POST /tenant/mail-signing-keys/pgp' => SignedInScreen::answered(self::key('pgp', self::PGP, true), 201),
        ]);
        $this->screen->open('section.mail_signing_keys');
        $this->screen->press(["\r", 'p']);

        // When
        $this->screen->press('y');

        // Then
        static::assertSame([1, 2, true], [
            $this->screen->requestsTo('/tenant/mail-signing-keys/pgp', 'POST'),
            $this->screen->requestsTo('/tenant/mail-signing-keys'),
            str_contains($this->screen->screen(), 'https://op.example/mail/pgp-keys'),
        ]);
    }

    #[Test]
    public function anSmimeKeyIsSetFromTheFileOfItsKeyAndTheFileOfItsCertificates(): void
    {
        // Given
        $directory = $this->files(0o600);
        $this->screen = new SignedInScreen([
            '/tenant/mail-signing-keys' => self::tenantKeys(),
            'PUT /tenant/mail-signing-keys/smime' => self::key('smime', self::SMIME, true),
        ]);
        $this->screen->open('section.mail_signing_keys');
        $this->screen->press(["\r", 's']);
        $this->screen->type($directory . '/mail.key');
        $this->screen->press("\r");
        $this->screen->type($directory . '/mail.crt');

        // When
        $this->screen->press("\r");

        // Then
        static::assertSame(
            [[json_encode(['private_key' => self::KEY, 'certificates' => self::CHAIN], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)], true],
            [
                $this->screen->bodiesTo('/tenant/mail-signing-keys/smime', 'PUT'),
                str_contains($this->screen->screen(), 'S/MIME mail is signed with the key'),
            ],
        );
    }

    /**
     * Whoever may read the private key signs the mail of the tenant, as whoever may read a profile acts for its client.
     */
    #[Test]
    public function aPrivateKeyOthersMayOpenIsNotSent(): void
    {
        // Given
        $directory = $this->files(0o644);
        $this->screen = new SignedInScreen(['/tenant/mail-signing-keys' => self::tenantKeys()]);
        $this->screen->open('section.mail_signing_keys');
        $this->screen->press(["\r", 's']);
        $this->screen->type($directory . '/mail.key');

        // When
        $this->screen->press("\r");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, false], [
            str_contains($screen, 'Nothing was sent: the private key'),
            str_contains($screen, 'File of its certificate'),
        ]);
    }

    /**
     * The current key of a format removed, the tenant signs nothing in that format: it is asked first.
     */
    #[Test]
    public function removingTheCurrentKeyIsAskedToBeConfirmedFirst(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/tenant/mail-signing-keys' => self::tenantKeys()]);
        $this->screen->open('section.mail_signing_keys');

        // When
        $this->screen->press(["\r", 'x']);

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo(sprintf('/tenant/mail-signing-keys/pgp/%s', self::PGP), 'DELETE'),
            str_contains($this->screen->screen(), 'It is the current key'),
        ]);
    }

    #[Test]
    public function aKeyIsRemovedOnceConfirmedAndTheListReadAgain(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/tenant/mail-signing-keys' => self::tenantKeys(),
            sprintf('DELETE /tenant/mail-signing-keys/pgp/%s', self::REPLACED) => self::key('pgp', self::REPLACED, false),
        ]);
        $this->screen->open('section.mail_signing_keys');
        $this->screen->press(["\r", "\e[B", 'x']);

        // When
        $this->screen->press('y');

        // Then
        static::assertSame([1, 2, true], [
            $this->screen->requestsTo(sprintf('/tenant/mail-signing-keys/pgp/%s', self::REPLACED), 'DELETE'),
            $this->screen->requestsTo('/tenant/mail-signing-keys'),
            str_contains($this->screen->screen(), 'is removed.'),
        ]);
    }

    #[Test]
    public function aRefusalIsSaidInTheWordsOfTheInstance(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/tenant/mail-signing-keys' => ['keys' => []],
            'POST /tenant/mail-signing-keys/pgp' => SignedInScreen::answered([
                'error' => 'conflict',
                'error_description' => 'This deployment writes no mail: it names no sender a key could sign for.',
            ], 409),
        ]);
        $this->screen->open('section.mail_signing_keys');
        $this->screen->press(["\r", 'p']);

        // When
        $this->screen->press('y');

        // Then
        static::assertStringContainsString('Nothing was changed: This deployment writes no mail', $this->screen->screen());
    }

    #[Test]
    public function theKeysOfTheSectionAreSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/tenant/mail-signing-keys' => self::tenantKeys()]);
        $this->screen->open('section.mail_signing_keys');

        // When
        $this->screen->press("\r");

        // Then
        $lines = explode("\n", $this->screen->screen());
        $last = $lines[count($lines) - 1];
        static::assertSame([true, true, true], [
            str_contains($last, 'generate an OpenPGP key'),
            str_contains($last, 'set an S/MIME key'),
            str_contains($last, 'remove'),
        ]);
    }

    /**
     * A directory of its own holding the private key, with those permissions, and its certificates.
     */
    private function files(int $keyPermissions): string
    {
        $this->directory = sprintf('%s/beffroi-tui-mail-%s', sys_get_temp_dir(), uniqid());
        mkdir($this->directory, 0o700);
        file_put_contents($this->directory . '/mail.key', self::KEY);
        chmod($this->directory . '/mail.key', $keyPermissions);
        file_put_contents($this->directory . '/mail.crt', self::CHAIN);
        chmod($this->directory . '/mail.crt', 0o644);

        return $this->directory;
    }

    /**
     * @return array<string, mixed>
     */
    private static function tenantKeys(): array
    {
        return ['keys' => [self::key('pgp', self::PGP, true), self::key('pgp', self::REPLACED, false)]];
    }

    /**
     * @return array<string, mixed>
     */
    private static function key(string $format, string $fingerprint, bool $current): array
    {
        return [
            'format' => $format,
            'fingerprint' => $fingerprint,
            'current' => $current,
            'senders' => ['no-reply@op.example'],
            'published' => '',
            'set_at' => $current ? '2026-11-20T08:00:00Z' : '2026-11-01T08:00:00Z',
            'not_after' => null,
            'replaced_at' => $current ? null : '2026-11-20T08:00:00Z',
        ];
    }
}
