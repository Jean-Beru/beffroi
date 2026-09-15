<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use function sprintf;

/**
 * An issuer whose ID tokens say what they would carry, in clear. Never leaves the test suite: the real
 * one writes a signed JWT (issue #8).
 */
final class FakeIdTokenIssuer implements IdTokenIssuerInterface
{
    /**
     * @var list<array{GrantedAuthorization, AccessToken}>
     */
    public private(set) array $issued = [];

    public function issue(GrantedAuthorization $authorization, AccessToken $accessToken, DateTimeImmutable $now): string
    {
        $this->issued[] = [$authorization, $accessToken];

        return sprintf('id:%s:%s:%s:%d', $authorization->client->clientId, $authorization->user->subject, $authorization->nonce ?? '-', $now->getTimestamp());
    }
}
