<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Dpop\DpopChallengeParameters;
use Beffroi\Oidc\Application\Token\Confirmations;
use Beffroi\Oidc\Domain\Token\CertificateConfirmationKind;
use Beffroi\Oidc\Domain\Token\KeyConfirmationKind;

final class Bindings
{
    public static function wired(): Confirmations
    {
        return new Confirmations([new CertificateConfirmationKind(), new KeyConfirmationKind()]);
    }

    /**
     * @return non-empty-list<string>
     */
    public static function schemes(): array
    {
        return self::wired()->servedTokenSchemes();
    }

    /**
     * RFC 9449 §7.1
     *
     * @return array<non-empty-string, array<non-empty-string, non-empty-string>>
     */
    public static function challengeParameters(): array
    {
        return new DpopChallengeParameters(
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
        )->challengeParameters();
    }
}
