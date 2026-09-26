<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Ciba;

use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Authorization\ResolvedRequestObject;
use Heidi\Oidc\Application\Ciba\SignedBackchannelRequest;
use Heidi\Oidc\Bridge\InMemory\InMemoryRequestObjectReplayGuard;
use Heidi\Oidc\Domain\Authorization\RequestObject;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §7.1.1 against the object alone. What a client sends and what the endpoint answers for it is
 * BackchannelAuthenticationHandlerTest's; what is here is the one state the endpoint cannot reach.
 */
final class SignedBackchannelRequestTest extends TestCase
{
    /**
     * RFC 9101 §4: an object reaches this rule with its claims validated, "exp" among them, because the
     * resolver validates before it hands anything over. One that arrives without it says the rule was
     * wired somewhere the resolver is not, which is a fault of the integration and not of the request.
     */
    #[Test]
    public function anObjectWithoutAnExpIsAnEndpointWiredWithoutTheResolver(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $client = Clients::backchannel($tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $rule = new SignedBackchannelRequest(new InMemoryRequestObjectReplayGuard());
        $object = new RequestObject(
            new UnverifiedJwt(
                'header.payload.signature',
                [
                    'alg' => 'ES256',
                ],
                [
                    'iat' => 1_774_512_000,
                    'jti' => 'b2f1c0a9-8e7d-4c6b-9a5f-0d1e2f3a4b5c',
                ],
            ),
        );

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A signed request object reaches this rule validated, and an exp is one of the claims that were asked of it (RFC 9101 section 4).');

        // When
        $rule->accept(new ResolvedRequestObject($object, []), $client);
    }
}
