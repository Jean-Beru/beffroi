<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Authorization\RequestObjectValidator;
use Beffroi\Oidc\Domain\Authorization\RequestObject;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RequestObjectValidatorTest extends TestCase
{
    private const string NOW = '2026-09-22T12:00:00+00:00';

    private Tenant $tenant;

    private Client $client;

    private RequestObjectValidator $validator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->validator = new RequestObjectValidator(new DateInterval('PT3600S'), new DateInterval('PT30S'));
    }

    /**
     * RFC 9101 §4
     */
    #[Test]
    public function itAcceptsAnObjectOfTheClientAddressedToThisProvider(): void
    {
        // Given
        $object = self::objectOf([
            'iss' => 'oidc-demo',
            'aud' => 'https://id.acme.example',
            'nbf' => $this->timestamp(),
            'exp' => $this->timestamp() + 300,
            'client_id' => 'oidc-demo',
        ]);

        // When
        $this->validator->validate($object, $this->client, $this->tenant, $this->now());

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * RFC 7519 §4.1.3
     */
    #[Test]
    public function anAudienceListNamingThisProviderIsAccepted(): void
    {
        // Given
        $object = self::objectOf([
            'iss' => 'oidc-demo',
            'aud' => ['https://other.example', 'https://id.acme.example'],
            'nbf' => $this->timestamp(),
            'exp' => $this->timestamp() + 300,
        ]);

        // When
        $this->validator->validate($object, $this->client, $this->tenant, $this->now());

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * RFC 9101 §4, §10.2, OIDC Core §6.1
     *
     * @param array<string, mixed> $claims
     */
    #[Test]
    #[DataProvider('provideObjectsThatAreRefused')]
    public function itRefusesAnObjectThatDoesNotSayWhatARequestObjectSays(array $claims, string $message): void
    {
        // Given
        $object = self::objectOf($claims);

        // Then
        $this->expectException(InvalidRequestObjectException::class);
        $this->expectExceptionMessageIsOrContains($message);

        // When
        $this->validator->validate($object, $this->client, $this->tenant, $this->now());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideObjectsThatAreRefused(): iterable
    {
        $now = new DateTimeImmutable(self::NOW)->getTimestamp();

        yield 'issued by another client' => [
            [
                'iss' => 'another-client',
                'aud' => 'https://id.acme.example',
                'nbf' => $now,
                'exp' => $now + 300,
            ],
            'The iss of a request object names the client that sends it',
        ];
        yield 'no issuer at all' => [
            [
                'aud' => 'https://id.acme.example',
                'nbf' => $now,
                'exp' => $now + 300,
            ],
            'The iss of a request object names the client that sends it',
        ];
        yield 'addressed to another provider' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://other.example',
                'nbf' => $now,
                'exp' => $now + 300,
            ],
            'The aud of a request object names the issuer of this provider',
        ];
        yield 'no audience at all' => [
            [
                'iss' => 'oidc-demo',
                'nbf' => $now,
                'exp' => $now + 300,
            ],
            'The aud of a request object names the issuer of this provider',
        ];
        yield 'naming another client inside' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'nbf' => $now,
                'exp' => $now + 300,
                'client_id' => 'another-client',
            ],
            'The client_id inside a request object is the one the request names outside it',
        ];
        yield 'without an "nbf"' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'exp' => $now + 300,
            ],
            'A request object carries an nbf',
        ];
        yield 'not valid yet' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'nbf' => $now + 31,
                'exp' => $now + 300,
            ],
            'The request object is not valid yet',
        ];
        yield 'without an "exp"' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'nbf' => $now,
            ],
            'A request object carries an exp',
        ];
        yield 'expired' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'nbf' => $now - 600,
                'exp' => $now - 31,
            ],
            'The request object has expired',
        ];
        yield 'expired at the edge of the leeway' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'nbf' => $now - 600,
                'exp' => $now - 30,
            ],
            'The request object has expired',
        ];
        yield 'standing longer than this provider accepts' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'nbf' => $now,
                'exp' => $now + 3601,
            ],
            'stays inside the lifetime this provider accepts',
        ];
        yield 'an "exp" that is not a number of seconds' => [
            [
                'iss' => 'oidc-demo',
                'aud' => 'https://id.acme.example',
                'nbf' => $now,
                'exp' => (string) ($now + 300),
            ],
            'A request object carries an exp',
        ];
    }

    #[Test]
    #[DataProvider('provideClocksInsideTheLeeway')]
    public function theClockOfAClientIsAllowedTheLeeway(int $notBefore, int $expiresAt): void
    {
        // Given
        $object = self::objectOf([
            'iss' => 'oidc-demo',
            'aud' => 'https://id.acme.example',
            'nbf' => $this->timestamp() + $notBefore,
            'exp' => $this->timestamp() + $expiresAt,
        ]);

        // When
        $this->validator->validate($object, $this->client, $this->tenant, $this->now());

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function provideClocksInsideTheLeeway(): iterable
    {
        yield 'a client ahead of the provider' => [30, 330];
        yield 'an object that expired within the leeway' => [-600, -29];
        yield 'an object standing exactly the lifetime this provider accepts' => [0, 3600];
    }

    /**
     * OIDC Core §6.1, decision 0006
     */
    #[Test]
    public function anUnsignedObjectIsNotAskedForTheClaimsThatBoundAProof(): void
    {
        // Given
        $object = self::unsignedObjectOf([
            'scope' => 'openid',
            'response_mode' => 'form_post',
            'client_id' => 'oidc-demo',
        ]);

        // When
        $this->validator->validate($object, $this->client, $this->tenant, $this->now());

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * OIDC Core §6.1
     */
    #[Test]
    public function anUnsignedObjectNamingAnotherClientIsRefused(): void
    {
        // Given
        $object = self::unsignedObjectOf([
            'client_id' => 'another-client',
        ]);

        // Then
        $this->expectException(InvalidRequestObjectException::class);
        $this->expectExceptionMessageIsOrContains('The client_id inside a request object is the one the request names outside it');

        // When
        $this->validator->validate($object, $this->client, $this->tenant, $this->now());
    }

    private function now(): DateTimeImmutable
    {
        return new DateTimeImmutable(self::NOW);
    }

    private function timestamp(): int
    {
        return $this->now()->getTimestamp();
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function objectOf(array $claims): RequestObject
    {
        return new RequestObject(
            new UnverifiedJwt(
                'the.compact.jws',
                [
                    'alg' => 'ES256',
                ],
                $claims,
            ),
        );
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function unsignedObjectOf(array $claims): RequestObject
    {
        return new RequestObject(
            new UnverifiedJwt(
                'the.unsigned.',
                [
                    'alg' => 'none',
                ],
                $claims,
            ),
        );
    }
}
