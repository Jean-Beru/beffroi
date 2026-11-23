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
     * Architecture §3.5
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

    /**
     * Decision 0062
     */
    #[Test]
    public function itSaysWhyItRefusedAndTheMethodItRefused(): void
    {
        // When
        $event = new ClientAuthenticationFailed(
            Fixtures::now(),
            Fixtures::tenant(),
            Fixtures::context(),
            ClientAuthenticationFailureReason::InvalidAssertion,
            'oidc-demo',
            'private_key_jwt',
        );

        // Then
        static::assertSame(['invalid_assertion', 'private_key_jwt'], [$event->refusalReason(), $event->refusedMethod()]);
    }
}
