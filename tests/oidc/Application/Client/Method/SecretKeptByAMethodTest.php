<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Method;

use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7592 §2.2, RFC 6749 §2.3.1, OIDC Core §9
 */
final class SecretKeptByAMethodTest extends TestCase
{
    private const string SECRET = 'a-secret-the-provider-handed-it-of-at-least-32-characters';

    #[Test]
    #[DataProvider('provideMethodsThatKeepASecret')]
    public function aMethodRecognisesTheSecretItKept(SecretKeepingMethodInterface $method): void
    {
        // Given
        $kept = $method->keep(self::SECRET, new FakePasswordHasher());

        // When / Then
        static::assertTrue($method->holdsSecret(self::SECRET, $kept));
    }

    #[Test]
    #[DataProvider('provideMethodsThatKeepASecret')]
    public function aMethodRecognisesNoOther(SecretKeepingMethodInterface $method): void
    {
        // Given
        $kept = $method->keep(self::SECRET, new FakePasswordHasher());

        // When / Then
        static::assertFalse($method->holdsSecret('a-secret-of-somebody-else-of-at-least-32-characters', $kept));
    }

    #[Test]
    #[DataProvider('provideSecretsKeptInAnotherShape')]
    public function aMethodRecognisesNothingKeptInAnotherShape(SecretKeepingMethodInterface $method, ClientSecretInterface $otherShape): void
    {
        // When / Then
        static::assertFalse($method->holdsSecret(self::SECRET, $otherShape));
    }

    /**
     * @return iterable<string, array{SecretKeepingMethodInterface}>
     */
    public static function provideMethodsThatKeepASecret(): iterable
    {
        yield 'the method the secret is presented to' => [Methods::clientSecretBasic()];

        yield 'the method that signs with the secret' => [Methods::clientSecretJwt()];
    }

    /**
     * @return iterable<string, array{SecretKeepingMethodInterface, ClientSecretInterface}>
     */
    public static function provideSecretsKeptInAnotherShape(): iterable
    {
        yield 'a secret of a client that signs with it, presented to the method that receives one' => [
            Methods::clientSecretBasic(),
            new SharedClientSecret(self::SECRET),
        ];

        yield 'a hashed secret, presented to the method that has to compute a MAC' => [
            Methods::clientSecretJwt(),
            new HashedClientSecret(new FakePasswordHasher()->hash(self::SECRET)),
        ];
    }
}
