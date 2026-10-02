<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\AsksTheUserOnAnotherDeviceInterface;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use LogicException;

/**
 * A grant that declares its user is asked somewhere other than in the client's own browser (RFC 8628
 * §3.3), which is what the device code grant declares, and grants nothing.
 */
final readonly class FakeUserOnAnotherDeviceGrant implements AsksTheUserOnAnotherDeviceInterface
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
