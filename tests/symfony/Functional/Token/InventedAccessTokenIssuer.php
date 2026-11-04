<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Token;

use DateTimeImmutable;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Port\AccessTokenShapeIssuerInterface;

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

    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken
    {
        return $this->issuer->addressFor($authorization);
    }

    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        $token = $this->issuer->issue($authorization, $addressed, $now);

        return new AccessToken(self::PREFIX . $token->value, $token->issuedAt, $token->expiresAt);
    }
}
