<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use App\Mail\PgpMailSigner;
use App\Tests\Symfony\Fixture\MailFixtures;
use App\Tests\Symfony\Fixture\MailSigningKeys;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use function bin2hex;
use function file_put_contents;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Part\AbstractMultipartPart;
use Symfony\Component\Process\Process;
use function sys_get_temp_dir;

/**
 * RFC 9580 §5.2, §5.5.2, §10.1, RFC 3156 §5: what this provider writes of OpenPGP, read by gpg, which wrote none of it.
 * Skipped on a machine that carries no gpg, the image of the QA tools among them.
 */
final class OpenPgpOracleTest extends TestCase
{
    private string $home;

    protected function setUp(): void
    {
        if (MailFixtures::gpg() === null) {
            static::markTestSkipped('gpg is not installed here.');
        }
        $this->home = sys_get_temp_dir() . '/openpgp-oracle-' . bin2hex(random_bytes(4));
        mkdir($this->home, 0o700);
    }

    protected function tearDown(): void
    {
        if (isset($this->home)) {
            new Process(['rm', '-rf', $this->home])->run();
        }
    }

    #[Test]
    public function gpgImportsTheKeyUnderItsFingerprintWithItsCertifiedUserId(): void
    {
        // Given
        $key = MailSigningKeys::pgp(Fixtures::tenant());

        // When
        $imported = $this->gpg(['--status-fd', '1', '--import'], $key->published);

        // Then
        $signatures = $this->gpg(['--with-colons', '--fixed-list-mode', '--check-signatures']);
        static::assertStringContainsString('[GNUPG:] IMPORT_OK 1 ' . $key->fingerprint, $imported);
        static::assertStringContainsString('::Acme <no-reply@acme.example>::', $signatures);
        static::assertMatchesRegularExpression('/^sig:!:/m', $signatures);
    }

    #[Test]
    public function gpgFindsTheSignatureOfAMailGoodUnderThatKey(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = MailSigningKeys::pgp($tenant);
        $this->gpg(['--import'], $key->published);
        $signed = new PgpMailSigner(new MockClock())->sign(
            new Email()
                ->from(MailSigningKeys::SENDER)
                ->to('alice@acme.example')
                ->subject('A sign-in is waiting')
                ->text("Open your account to answer.\nAcme"),
            $key,
            Keys::sealer()->unseal($tenant, $key->sealedPrivateJwk),
        );
        $body = $signed->getBody();
        static::assertInstanceOf(AbstractMultipartPart::class, $body);
        file_put_contents($this->home . '/signed', $body->getParts()[0]->toString());
        file_put_contents($this->home . '/signature.asc', $body->getParts()[1]->bodyToString());

        // When
        $status = $this->gpg(['--status-fd', '1', '--verify', $this->home . '/signature.asc', $this->home . '/signed']);

        // Then
        static::assertStringContainsString('[GNUPG:] VALIDSIG ' . $key->fingerprint, $status);
    }

    /**
     * @param list<string> $arguments
     */
    private function gpg(array $arguments, ?string $input = null): string
    {
        $process = new Process(['gpg', '--batch', '--no-autostart', ...$arguments], null, ['GNUPGHOME' => $this->home], $input);
        $process->run();

        return $process->getOutput() . $process->getErrorOutput();
    }
}
