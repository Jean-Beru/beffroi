<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Application\Token\ExchangesATokenInterface;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use LogicException;

/**
 * A grant that declares it takes a token as its input and gives a token back (RFC 8693 §2.1), which is what
 * the token exchange declares, and grants nothing.
 */
final readonly class FakeExchangingGrant implements ExchangesATokenInterface
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
