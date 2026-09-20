<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Application\Token\GrantInterface;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use LogicException;

/**
 * A grant that names its type and grants nothing, for what reads the grants wired (the discovery document).
 */
final readonly class FakeGrant implements GrantInterface
{
    public function __construct(
        private GrantType $grantType,
    ) {
    }

    public function grantType(): GrantType
    {
        return $this->grantType;
    }

    public function grant(Client $client, TokenRequest $request, RequestContext $context): IssuedTokens
    {
        throw new LogicException('The fake grant grants nothing.');
    }
}
