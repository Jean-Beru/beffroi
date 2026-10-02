<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClientAuthenticationFailedTest extends TestCase
{
    /**
     * Architecture §3.5: every event says when, in which tenant and from which request.
     */
    #[Test]
    public function itIsADomainEventWithTheRequestContext(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $context = Fixtures::context();

        // When
        $event = new ClientAuthenticationFailed(
            Fixtures::now(),
            $tenant,
            $context,
            ClientAuthenticationFailureReason::InvalidSecret,
            'oidc-demo',
            'client_secret_basic',
        );

        // Then
        static::assertEquals(Fixtures::now(), $event->occurredAt);
        static::assertSame($tenant, $event->tenant);
        static::assertSame($context, $event->context);
        static::assertSame('invalid_secret', $event->reason->value);
        static::assertSame('oidc-demo', $event->clientId);
        static::assertSame('client_secret_basic', $event->method);
    }
}
