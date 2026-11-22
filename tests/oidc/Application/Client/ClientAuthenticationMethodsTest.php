<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use function array_map;
use Beffroi\Oidc\Application\Client\ClientAuthenticationMethods;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClientAuthenticationMethodsTest extends TestCase
{
    #[Test]
    public function itKeepsTheMethodsInTheOrderTheyAreWired(): void
    {
        // When
        $methods = new ClientAuthenticationMethods([Methods::none(), Methods::clientSecretBasic()])->clientAuthenticationMethods();

        // Then
        static::assertSame(
            ['none', 'client_secret_basic'],
            array_map(static fn (ClientAuthenticationMethodInterface $method): string => $method->name(), $methods),
        );
    }

    #[Test]
    public function aMethodWiredTwiceIsAMistake(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client authentication method "none" is wired twice.');

        // When
        new ClientAuthenticationMethods([Methods::none(), Methods::none()]);
    }

    #[Test]
    public function aProviderThatAuthenticatesNoClientIsAMistake(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider authenticates its clients with at least one method.');

        // When
        new ClientAuthenticationMethods([]);
    }
}
