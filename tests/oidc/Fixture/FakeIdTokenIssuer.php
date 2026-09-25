<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\UserAuthorizationInterface;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use function sprintf;

/**
 * An issuer whose ID tokens say what they would carry, in clear. Never leaves the test suite: the real
 * one, JwtIdTokenIssuer, writes a signed JWT.
 */
final class FakeIdTokenIssuer implements IdTokenIssuerInterface
{
    /**
     * @var list<array{UserAuthorizationInterface, AccessToken}>
     */
    public private(set) array $issued = [];

    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, DateTimeImmutable $now): string
    {
        $this->issued[] = [$authorization, $accessToken];

        return sprintf(
            'id:%s:%s:%s:%d',
            $authorization->client->registration->clientId,
            $authorization->user->subject,
            $authorization->nonce ?? '-',
            $now->getTimestamp(),
        );
    }
}
