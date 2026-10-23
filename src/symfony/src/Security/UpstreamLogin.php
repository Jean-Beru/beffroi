<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Saml\Domain\Upstream\AuthnContextMethods;
use DateTimeImmutable;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The login of the firewall an upstream identity provider proves (beffroi/saml S-52, S-57): what its assertion proved,
 * read from the badge the assertion consumer service put on the passport, dated by its AuthnInstant; every method it
 * may prove, "fed" and the methods its classes of authentication map to exactly, is what the provider announces of it.
 * Tagged "beffroi.login" only when the service provider of the tenant is enabled, so that a deployment that receives no
 * assertion announces nothing of one.
 */
final readonly class UpstreamLogin implements DatesItsProofsInterface
{
    public function proofs(Passport $passport): ?array
    {
        $badge = $passport->getBadge(UpstreamCredentials::class);

        return $badge instanceof UpstreamCredentials ? $badge->methods : null;
    }

    public function everyProvableMethod(): array
    {
        return AuthnContextMethods::everyProvable();
    }

    public function provenAt(Passport $passport): ?DateTimeImmutable
    {
        $badge = $passport->getBadge(UpstreamCredentials::class);

        return $badge instanceof UpstreamCredentials ? $badge->provenAt : null;
    }
}
