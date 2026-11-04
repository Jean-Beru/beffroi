<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Oidc\Application\Authorization\RequestObjectResolver;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\RequestObjects;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 9101 §6.1, OIDC Core §6.1
 */
final class EncryptedRequestObjectTest extends TestCase
{
    private Tenant $tenant;

    private MockClock $clock;

    private TenantKey $encryption;

    private RequestObjectResolver $resolver;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-09-22T12:00:00+00:00');
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::sendingRequestObjects($this->tenant));
        $clients->save(Clients::sendingRequestObjects($this->tenant, new UnsignedRequestObjects(), clientId: 'unsigned-client'));
        $keys = new Jwts($this->tenant);
        $this->encryption = $keys->activate(Algorithms::ecdhEsA256Kw(), Keys::encryptionPair());
        $this->resolver = RequestObjects::resolver($clients, $this->clock, decrypter: new JwtLibraryJweDecrypter($keys->keys, Algorithms::encryption()));
    }

    #[Test]
    public function anObjectEncryptedToThePublishedKeyIsReadLikeOneInClear(): void
    {
        // Given
        $object = RequestObjects::encryptedTo(
            $this->encryption->publicJwk,
            RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
                'response_type' => 'code',
                'redirect_uri' => 'https://jar.example/callback',
                'scope' => 'openid profile',
            ])),
            [
                'cty' => 'JWT',
            ],
        );

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'jar-client',
            'request' => $object,
        ])?->parameters;

        // Then
        static::assertSame(
            [
                'client_id' => 'jar-client',
                'response_type' => 'code',
                'redirect_uri' => 'https://jar.example/callback',
                'scope' => 'openid profile',
            ],
            $parameters,
        );
    }

    /**
     * RFC 9101 §6.2
     */
    #[Test]
    public function theSignatureInsideTheJweIsVerifiedAgainstTheKeysOfTheClient(): void
    {
        // Given
        $other = new JWK([
            ...Algorithms::es256()->generateKey()->all(),
            'kid' => ClientAssertions::KEY_ID,
        ]);
        $object = RequestObjects::encryptedTo(
            $this->encryption->publicJwk,
            RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now()), [], $other),
        );

        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The signature of the request object verifies against no key the client publishes.',
        );
    }

    /**
     * OIDC Registration §2, decision 0006
     */
    #[Test]
    public function theClaimsOfTheClientThatRegisteredNoSignatureAreReadFromTheJwe(): void
    {
        // Given
        $object = RequestObjects::encryptedTo(
            $this->encryption->publicJwk,
            JwtPayload::encode(RequestObjects::claims('unsigned-client', $this->tenant->issuer->value, $this->clock->now(), [
                'response_mode' => 'form_post',
                'scope' => 'openid',
            ])),
        );

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'unsigned-client',
            'request' => $object,
        ])?->parameters;

        // Then
        static::assertSame('form_post', $parameters['response_mode'] ?? null);
        static::assertSame('unsigned-client', $parameters['client_id'] ?? null);
    }

    /**
     * RFC 8259 §2
     */
    #[Test]
    public function theClaimsAreReadWhateverWhitespaceSurroundsThem(): void
    {
        // Given
        $object = RequestObjects::encryptedTo(
            $this->encryption->publicJwk,
            "\n " . JwtPayload::encode(RequestObjects::claims('unsigned-client', $this->tenant->issuer->value, $this->clock->now(), [
                'scope' => 'openid',
            ])),
        );

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'unsigned-client',
            'request' => $object,
        ])?->parameters;

        // Then
        static::assertSame('openid', $parameters['scope'] ?? null);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function theClaimsOfAClientThatRegisteredAnAlgorithmAreRefused(): void
    {
        // Given
        $object = RequestObjects::encryptedTo(
            $this->encryption->publicJwk,
            JwtPayload::encode(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())),
        );

        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).',
        );
    }

    /**
     * Architecture §3.3
     */
    #[Test]
    public function anObjectEncryptedToAKeyThatHasRetiredIsRefused(): void
    {
        // Given
        $object = RequestObjects::encryptedTo(
            $this->encryption->publicJwk,
            RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())),
        );
        $this->encryption->startRetiring($this->clock->now(), $this->clock->now());
        $this->encryption->retire($this->clock->now());

        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The request object does not open with a key this provider publishes for encryption (RFC 9101 section 6.1).',
        );
    }

    /**
     * RFC 7516 §4.1.6
     */
    #[Test]
    public function anObjectEncryptedToAKeyTheTenantNeverPublishedIsRefused(): void
    {
        // Given
        /** @var array<string, mixed> $elsewhere */
        $elsewhere = [
            ...Algorithms::ecdhEsA256Kw()->generateKey()->toPublic()->all(),
            'alg' => Algorithms::ecdhEsA256Kw()->name(),
            'kid' => 'a-key-of-somebody-else',
        ];
        $object = RequestObjects::encryptedTo(
            $elsewhere,
            RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())),
        );

        // When / Then
        $this->refuses(
            [
                'client_id' => 'jar-client',
                'request' => $object,
            ],
            'invalid_request_object',
            'The request object does not open with a key this provider publishes for encryption (RFC 9101 section 6.1).',
        );
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function refuses(array $parameters, string $error, string $description): void
    {
        // When
        try {
            $this->resolver->resolve($this->tenant, $parameters);
            static::fail('The request should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame($error, $exception->error);
            static::assertSame($description, $exception->errorDescription);
            static::assertFalse($exception->redirectable);
        }
    }
}
