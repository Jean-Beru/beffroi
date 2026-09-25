<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Application\Token\ActsForTheClientItselfInterface;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use LogicException;

/**
 * A grant that declares a client uses it for itself, with nobody signed in behind it (RFC 6749 §4.4),
 * which is what the client credentials grant declares, and grants nothing.
 */
final readonly class FakeClientActingGrant implements ActsForTheClientItselfInterface
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
