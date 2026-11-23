<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Ciba;

use function array_values;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Authorization\ResolvedRequestObject;
use Beffroi\Oidc\Application\Ciba\SignedBackchannelRequest;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRequestObjectReplayGuard;
use Beffroi\Oidc\Domain\Authorization\RequestObject;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §7.1.1
 */
final class SignedBackchannelRequestTest extends TestCase
{
    /**
     * RFC 9101 §4
     */
    #[Test]
    public function anObjectWithoutAnExpIsAnEndpointWiredWithoutTheResolver(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $client = Clients::backchannel($tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $rule = new SignedBackchannelRequest(new InMemoryRequestObjectReplayGuard(), new DateInterval('PT30S'));
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

    /**
     * CIBA Core §7.1.1, RFC 9101 §4
     */
    #[Test]
    public function itRemembersASignedRequestUntilTheLastInstantItWouldBeAccepted(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $client = Clients::backchannel($tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $replays = new InMemoryRequestObjectReplayGuard();
        $rule = new SignedBackchannelRequest($replays, new DateInterval('PT30S'));
        $object = new RequestObject(
            new UnverifiedJwt(
                'header.payload.signature',
                [
                    'alg' => 'ES256',
                ],
                [
                    'iat' => 1_774_512_000,
                    'exp' => 1_774_512_300,
                    'jti' => 'b2f1c0a9-8e7d-4c6b-9a5f-0d1e2f3a4b5c',
                ],
            ),
        );

        // When
        $rule->accept(new ResolvedRequestObject($object, []), $client);

        // Then
        static::assertEquals([new DateTimeImmutable('@1774512330')], array_values($replays->seen));
    }
}
