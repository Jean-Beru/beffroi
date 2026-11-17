<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Application\Key\HeldSigningAlgorithms;
use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;

/**
 * What any tenant of a test can sign with: the wired algorithms it is given an active key for.
 */
final class HeldSigning
{
    public static function everyAlgorithm(?SignatureAlgorithmsInterface $wired = null): HeldSigningAlgorithms
    {
        $wired ??= Algorithms::all();

        return self::of($wired->all(), $wired);
    }

    /**
     * @param list<SignatureAlgorithmInterface> $held
     */
    public static function of(array $held, ?SignatureAlgorithmsInterface $wired = null): HeldSigningAlgorithms
    {
        return new HeldSigningAlgorithms($wired ?? Algorithms::all(), new KeysOfEveryTenant($held));
    }
}
