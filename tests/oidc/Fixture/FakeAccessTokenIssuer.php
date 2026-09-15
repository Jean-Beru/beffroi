<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use DateInterval;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use function sprintf;

/**
 * An issuer whose tokens say who they were minted for, in clear, and live ten minutes. Never leaves the
 * test suite: the real one writes a signed at+jwt (issue #8).
 */
final class FakeAccessTokenIssuer implements AccessTokenIssuerInterface
{
    /**
     * @var list<GrantedAuthorization>
     */
    public private(set) array $issued = [];

    public function __construct(
        private readonly DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken
    {
        $this->issued[] = $authorization;

        return new AccessToken(sprintf('at:%s:%s:%d', $authorization->client->clientId, $authorization->user->subject, $now->getTimestamp()), $now, $now->add($this->lifetime));
    }
}
