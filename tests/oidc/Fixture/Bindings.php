<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Token\Confirmations;
use Beffroi\Oidc\Domain\Token\CertificateConfirmationKind;
use Beffroi\Oidc\Domain\Token\KeyConfirmationKind;

/**
 * The two ways this provider binds a token, wired as the bundle wires them: the certificate of the
 * handshake and the key of a proof. A test that reads a "cnf" back, or that asks what schemes a
 * resource serves, takes them as a deployment has them.
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
}
