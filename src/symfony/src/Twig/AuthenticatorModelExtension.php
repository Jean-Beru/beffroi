<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Twig;

use Beffroi\Core\Application\Credential\AuthenticatorModels;
use Beffroi\Core\Domain\Credential\AuthenticatorModel;
use Beffroi\Core\Domain\Credential\ModelDeclaringCredentialInterface;
use Twig\Attribute\AsTwigFilter;

/**
 * The make and model of the authenticator of a passkey, as the page of the passkeys names it (issue #983): what
 * the first source that knows the AAGUID writes, or nothing, which the page says as an unknown authenticator.
 * Read from what the console stored, so that nothing is fetched while the page is served.
 */
final readonly class AuthenticatorModelExtension
{
    public function __construct(
        private AuthenticatorModels $models,
    ) {
    }

    #[AsTwigFilter(name: 'beffroi_authenticator')]
    public function model(ModelDeclaringCredentialInterface $credential): ?AuthenticatorModel
    {
        return $this->models->of($credential);
    }
}
