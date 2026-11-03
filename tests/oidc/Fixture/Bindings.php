<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Dpop\DpopChallengeParameters;
use Beffroi\Oidc\Application\Token\Confirmations;
use Beffroi\Oidc\Domain\Token\CertificateConfirmationKind;
use Beffroi\Oidc\Domain\Token\KeyConfirmationKind;

/**
 * The two ways this provider binds a token, wired as the bundle wires them: the certificate of the
 * handshake and the key of a proof. A test that reads a "cnf" back, or that asks what schemes a
 * resource serves and what their challenges say of them, takes them as a deployment has them.
 */
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
     * What the challenge of each scheme says whatever the refusal: under "DPoP", the algorithms of the
     * fixture of the core, the ones a proof may be signed with (RFC 9449 §7.1).
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
