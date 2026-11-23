<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Mail\MailEncrypterInterface;
use App\Mail\MailProtection;
use App\Mail\MailSignerInterface;
use App\Mail\OpenedMailSigningKeys;
use App\Mail\PgpMailSigner;
use App\Mail\PgpMime;
use App\Mail\Smime;
use App\Mail\SmimeMailSigner;
use Beffroi\Core\Bridge\InMemory\InMemoryMailSigningKeyRepository;
use Beffroi\Core\Port\MailSigningKeyRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Keys;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;

/**
 * The protection of a mail as the application wires it, over keys held in memory and sealed by the sealer of the
 * suite.
 */
final class MailProtections
{
    public static function plain(): MailProtection
    {
        return self::over(new InMemoryMailSigningKeyRepository(), new MockClock());
    }

    /**
     * @param list<MailSignerInterface>|null    $signers
     * @param list<MailEncrypterInterface>|null $encrypters
     */
    public static function over(
        MailSigningKeyRepositoryInterface $keys,
        ClockInterface $clock,
        ?array $signers = null,
        ?array $encrypters = null,
    ): MailProtection {
        $signers ??= [new SmimeMailSigner(), new PgpMailSigner($clock)];

        return new MailProtection(
            $signers,
            $encrypters ?? [new Smime(), new PgpMime()],
            $keys,
            new OpenedMailSigningKeys(Keys::sealer(), $keys, $signers),
            $clock,
        );
    }
}
