<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Token;

use DateTimeImmutable;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Port\AccessTokenShapeIssuerInterface;

/**
 * A third shape of access token, wired into the test kernel under a name no class of the module knows
 * (issue #239): a value of the opaque shape behind a prefix of its own, which is enough to prove that a
 * deployment adds a shape by writing two classes and tagging them, and that nothing in `src` was edited
 * for the token endpoint to mint it or for a resource to read it back.
 *
 * Never leaves the test suite: what it writes is not a format anybody specified.
 */
final readonly class InventedAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    public const string NAME = 'invented';

    public const string PREFIX = 'invented~';

    public function __construct(
        private OpaqueAccessTokenIssuer $issuer,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function address(Client $client): AddressedAccessToken
    {
        return $this->issuer->address($client);
    }

    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        $token = $this->issuer->issue($authorization, $addressed, $now);

        return new AccessToken(self::PREFIX . $token->value, $token->issuedAt, $token->expiresAt);
    }
}
