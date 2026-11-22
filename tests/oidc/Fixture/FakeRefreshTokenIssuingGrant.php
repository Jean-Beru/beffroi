<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\IssuesRefreshTokensInterface;
use Beffroi\Oidc\Application\Token\SendsTheUserToTheClientInterface;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use LogicException;

/**
 * RFC 6749 §4.1.4, §3.1.2
 */
final readonly class FakeRefreshTokenIssuingGrant implements IssuesRefreshTokensInterface, SendsTheUserToTheClientInterface
{
    public function __construct(
        private GrantTypeName $grantType,
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return $this->grantType;
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        throw new LogicException('The fake grant grants nothing.');
    }
}
