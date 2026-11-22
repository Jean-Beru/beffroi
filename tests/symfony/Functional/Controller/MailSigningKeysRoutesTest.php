<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Mail\PgpSigningKeys;
use App\Mail\SmimeSigningKeys;
use App\Tests\Symfony\Fixture\TenantMailSigningKeys;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Key\MailSigningKey;
use Beffroi\Core\Port\MailSigningKeyRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function substr_count;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0051, RFC 8555 §9.1, RFC 3156 §7: the keys the tenant signs its mail with, served from its origin to anyone,
 * and nothing for a format it holds no key of.
 */
final class MailSigningKeysRoutesTest extends BrowserTestCase
{
    #[Test]
    public function aTenantWithNoSmimeKeyServesNoCertificate(): void
    {
        // When
        $this->browser->request('GET', '/mail/smime-certificate');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function theCertificateOfTheCurrentKeyIsServedWithItsChain(): void
    {
        // Given
        $replaced = self::smime('op-sender');
        $replaced->replace(self::now());
        self::keys()->save($replaced);
        $current = self::smime('op-sender-next');
        self::keys()->save($current);

        // When
        $this->browser->request('GET', '/mail/smime-certificate');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_OK, 'application/pem-certificate-chain', $current->published],
            [$response->getStatusCode(), $response->headers->get('Content-Type'), $response->getContent()],
        );
    }

    #[Test]
    public function aTenantWithNoOpenPgpKeyServesNoKey(): void
    {
        // When
        $this->browser->request('GET', '/mail/pgp-keys');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function theCurrentOpenPgpKeyAndTheKeyItReplacedAreServed(): void
    {
        // Given
        $replaced = self::pgp();
        $replaced->replace(self::now());
        self::keys()->save($replaced);
        self::keys()->save(self::pgp());

        // When
        $this->browser->request('GET', '/mail/pgp-keys');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/pgp-keys', $response->headers->get('Content-Type'));
        static::assertSame(2, substr_count((string) $response->getContent(), '-----BEGIN PGP PUBLIC KEY BLOCK-----'));
    }

    #[Test]
    public function aKeyOfOneFormatServesNothingOfTheOther(): void
    {
        // Given
        self::keys()->save(self::pgp());

        // When
        $this->browser->request('GET', '/mail/smime-certificate');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    private static function keys(): MailSigningKeyRepositoryInterface
    {
        return self::service('test.beffroi.mail_signing_keys', MailSigningKeyRepositoryInterface::class);
    }

    private static function smime(string $name): MailSigningKey
    {
        $asked = TenantMailSigningKeys::asked($name);

        return self::service('test.beffroi.smime_signing_keys', SmimeSigningKeys::class)->of(
            self::tenant(),
            $asked['private_key'],
            $asked['certificates'],
            new EmailAddress('no-reply@op.test'),
        );
    }

    private static function pgp(): MailSigningKey
    {
        return self::service('test.beffroi.pgp_signing_keys', PgpSigningKeys::class)->draw(self::tenant(), new EmailAddress('no-reply@op.test'));
    }
}
