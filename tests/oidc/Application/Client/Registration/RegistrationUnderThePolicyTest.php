<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\Registration\KeptRegistration;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Tests\Fixture\Registrations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §3.2.1: the provider assigns a secret exactly when the registered method proves one. The one
 * thing that reads a registration the provider is about to write is where that is decided, so a creation
 * and a replacement decide it the same way.
 */
final class RegistrationUnderThePolicyTest extends TestCase
{
    private const string SECRET = 'a-secret-the-provider-handed-it-of-at-least-32-characters';

    #[Test]
    public function aClientWhoseMethodProvesNoSecretIsHandedNone(): void
    {
        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // Then
        static::assertNull($kept->secret);
        static::assertNull($kept->drawnSecret);
    }

    #[Test]
    public function aClientWhoseMethodProvesASecretAndHoldsNoneIsHandedOne(): void
    {
        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertIsString($kept->drawnSecret);
        static::assertInstanceOf(HashedClientSecret::class, $kept->secret);
    }

    /**
     * A client that already holds the secret its method proves keeps it: nothing is drawn, so nothing is
     * answered, which is what makes a replacement leave a secret alone (RFC 7592 §2.2).
     */
    #[Test]
    public function aClientThatAlreadyHoldsTheSecretItsMethodProvesKeepsIt(): void
    {
        // Given
        $held = new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET));

        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
        ], $held);

        // Then
        static::assertSame($held, $kept->secret);
        static::assertNull($kept->drawnSecret);
    }

    /**
     * A secret kept in a shape the registered method does not verify against is no secret for it, so one is
     * drawn: a client that registers the method signing with its secret cannot sign with a hash.
     */
    #[Test]
    public function aClientThatHoldsASecretOfAnotherShapeIsHandedOneItsMethodCanUse(): void
    {
        // Given
        $held = new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET));

        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_jwt',
        ], $held);

        // Then
        static::assertIsString($kept->drawnSecret);
        static::assertInstanceOf(SharedClientSecret::class, $kept->secret);
    }

    /**
     * Decision 0017: a tenant that has no policy writes nothing on the registration it has none for.
     */
    #[Test]
    public function aTenantWithoutAPolicyWritesNothingOnTheRegistration(): void
    {
        // When
        $kept = $this->read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame([], $kept->assigned);
    }

    /**
     * @param array<string, mixed> $members
     */
    private function read(array $members, ?ClientSecretInterface $held = null): KeptRegistration
    {
        return Registrations::underThePolicy()->read(Fixtures::tenant(), 'drawn-identifier', [], $members, null, $held);
    }
}
