<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Mail\PgpSigningKeys;
use App\Mail\SmimeSigningKeys;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Key\MailSigningKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Keys;
use DateTimeImmutable;
use Symfony\Component\Clock\MockClock;

/**
 * Mail signing keys of a tenant as the administration API sets them, sealed by the sealer of the suite.
 */
final class MailSigningKeys
{
    public const string SENDER = 'no-reply@acme.example';

    /**
     * @param string $name "sender" or "sender-next", the S/MIME keys "Acme Test CA" issued for the sender
     */
    public static function smime(Tenant $tenant, string $name = 'sender', ?DateTimeImmutable $now = null): MailSigningKey
    {
        return new SmimeSigningKeys(Keys::sealer(), new MockClock($now ?? new DateTimeImmutable('2026-11-22T10:00:00+00:00')))->of(
            $tenant,
            MailFixtures::read($name . '-key.pem'),
            MailFixtures::read($name . '-certificate.pem') . MailFixtures::read('ca-certificate.pem'),
            new EmailAddress(self::SENDER),
        );
    }

    public static function pgp(Tenant $tenant, ?DateTimeImmutable $now = null): MailSigningKey
    {
        return new PgpSigningKeys(Keys::sealer(), new MockClock($now ?? new DateTimeImmutable('2026-11-22T10:00:00+00:00')))->draw(
            $tenant,
            new EmailAddress(self::SENDER),
        );
    }
}
