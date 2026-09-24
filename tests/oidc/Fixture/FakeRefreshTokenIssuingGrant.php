<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Token\IssuesRefreshTokensInterface;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use LogicException;

/**
 * A grant that declares its response may carry a refresh token (RFC 6749 §4.1.4) and grants nothing.
 */
final readonly class FakeRefreshTokenIssuingGrant implements IssuesRefreshTokensInterface
{
    public function __construct(
        private GrantTypeName $grantType,
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return $this->grantType;
    }

    public function grant(AuthenticatedClient $client, TokenRequest $request, RequestContext $context): IssuedTokens
    {
        throw new LogicException('The fake grant grants nothing.');
    }
}
