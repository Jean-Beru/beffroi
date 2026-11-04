<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use function array_fill;
use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientIdentifierDrawer;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * RFC 7591 §3.2.1
 */
final class ClientIdentifierDrawerTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryClientRepository $clients;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientRepository();
    }

    #[Test]
    public function itDrawsTheIdentifierOfAClientNobodyHolds(): void
    {
        // Given
        $drawer = $this->drawer([self::bytes("\x01")]);

        // When
        $clientId = $drawer->drawFor($this->tenant);

        // Then
        static::assertSame(Base64Url::encode(self::bytes("\x01")), $clientId);
    }

    #[Test]
    public function aDrawnIdentifierASourceAlreadyHoldsIsDrawnAgain(): void
    {
        // Given
        $taken = Base64Url::encode(self::bytes("\x01"));
        $this->clients->save(Clients::public($this->tenant, $taken));
        $drawer = $this->drawer([self::bytes("\x01"), self::bytes("\x02")]);

        // When
        $clientId = $drawer->drawFor($this->tenant);

        // Then
        static::assertSame(Base64Url::encode(self::bytes("\x02")), $clientId);
    }

    #[Test]
    public function anIdentifierHeldUnderAnotherTenantIsFreeHere(): void
    {
        // Given
        $taken = Base64Url::encode(self::bytes("\x01"));
        $this->clients->save(Clients::public(Fixtures::tenant('other', 'https://id.other.example'), $taken));
        $drawer = $this->drawer([self::bytes("\x01")]);

        // When
        $clientId = $drawer->drawFor($this->tenant);

        // Then
        static::assertSame($taken, $clientId);
    }

    #[Test]
    public function itRefusesWhenEveryDrawIsAlreadyHeld(): void
    {
        // Given
        $bytes = self::bytes("\x01");
        $this->clients->save(Clients::public($this->tenant, Base64Url::encode($bytes)));
        $drawer = $this->drawer(array_fill(0, 3, $bytes));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Three drawn client identifiers were already held by the tenant "acme".');

        // When
        $drawer->drawFor($this->tenant);
    }

    /**
     * @param list<string> $bytes
     */
    private function drawer(array $bytes): ClientIdentifierDrawer
    {
        return new ClientIdentifierDrawer(new SecretDrawer(new FixedRandomness($bytes)), new RegisteredClients([$this->clients]));
    }

    private static function bytes(string $byte): string
    {
        return str_repeat($byte, DrawnSecret::LENGTH);
    }
}
