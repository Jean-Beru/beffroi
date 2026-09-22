<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Authorization;

use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\RequestObjects;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #189, RFC 9101 §6.1 and OIDC Core §6.1: the request object a client encrypted to a key the
 * tenant publishes. The provider opens the JWE with that key, then reads what comes out exactly as it
 * reads an object that arrived in clear, and what the object says of the request is the request.
 *
 * The keys of the tenant are the ones its JWK Set publishes, so an object encrypted to a key that has
 * retired opens with nothing, and the refusal is the refusal of an object, never a redirection.
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

    /**
     * The acceptance of issue #189: an object encrypted to the published key is served exactly as the
     * same object signed and in clear, its parameters being the request.
     */
    #[Test]
    public function anObjectEncryptedToThePublishedKeyIsReadLikeOneInClear(): void
    {
        // Given
        $object = RequestObjects::encryptedTo($this->encryption->publicJwk, RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now(), [
            'response_type' => 'code',
            'redirect_uri' => 'https://jar.example/callback',
            'scope' => 'openid profile',
        ])), [
            'cty' => 'JWT',
        ]);

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'jar-client',
            'request' => $object,
        ]);

        // Then
        static::assertSame([
            'client_id' => 'jar-client',
            'response_type' => 'code',
            'redirect_uri' => 'https://jar.example/callback',
            'scope' => 'openid profile',
        ], $parameters);
    }

    /**
     * RFC 9101 §6.2: the encryption says who may read the request and never who wrote it, so the
     * signature inside the JWE is verified against the keys the client publishes as any other is.
     */
    #[Test]
    public function theSignatureInsideTheJweIsVerifiedAgainstTheKeysOfTheClient(): void
    {
        // Given
        $other = new JWK([
            ...Algorithms::es256()->generateKey()
                ->all(),
            'kid' => ClientAssertions::KEY_ID,
        ]);
        $object = RequestObjects::encryptedTo($this->encryption->publicJwk, RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now()), [], $other));

        // When / Then
        $this->refuses([
            'client_id' => 'jar-client',
            'request' => $object,
        ], 'invalid_request_object', 'The signature of the request object verifies against no key the client publishes.');
    }

    /**
     * OIDC Registration §2, the named exception of decision 0006: the client that registered "none"
     * encrypts its claims themselves, and they are read as the unsigned object they are.
     */
    #[Test]
    public function theClaimsOfTheClientThatRegisteredNoSignatureAreReadFromTheJwe(): void
    {
        // Given
        $object = RequestObjects::encryptedTo($this->encryption->publicJwk, JwtPayload::encode(RequestObjects::claims('unsigned-client', $this->tenant->issuer->value, $this->clock->now(), [
            'response_mode' => 'form_post',
            'scope' => 'openid',
        ])));

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'unsigned-client',
            'request' => $object,
        ]);

        // Then
        static::assertSame('form_post', $parameters['response_mode'] ?? null);
        static::assertSame('unsigned-client', $parameters['client_id'] ?? null);
    }

    /**
     * RFC 8259 §2: whitespace around a JSON object is insignificant, and a claims set padded with it is
     * read as the claims set it is rather than taken for a token.
     */
    #[Test]
    public function theClaimsAreReadWhateverWhitespaceSurroundsThem(): void
    {
        // Given
        $object = RequestObjects::encryptedTo($this->encryption->publicJwk, "\n " . JwtPayload::encode(RequestObjects::claims('unsigned-client', $this->tenant->issuer->value, $this->clock->now(), [
            'scope' => 'openid',
        ])));

        // When
        $parameters = $this->resolver->resolve($this->tenant, [
            'client_id' => 'unsigned-client',
            'request' => $object,
        ]);

        // Then
        static::assertSame('openid', $parameters['scope'] ?? null);
    }

    /**
     * Decision 0006: encrypting claims to the provider proves nothing about who wrote them, so a client
     * that registered an algorithm is refused them exactly as it is refused an unsigned object in clear.
     */
    #[Test]
    public function theClaimsOfAClientThatRegisteredAnAlgorithmAreRefused(): void
    {
        // Given
        $object = RequestObjects::encryptedTo($this->encryption->publicJwk, JwtPayload::encode(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())));

        // When / Then
        $this->refuses([
            'client_id' => 'jar-client',
            'request' => $object,
        ], 'invalid_request_object', 'The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).');
    }

    /**
     * Architecture §3.3: an encryption key is openable as long as it is published and no longer; the
     * same object that was read a moment ago is refused once the key it names has retired.
     */
    #[Test]
    public function anObjectEncryptedToAKeyThatHasRetiredIsRefused(): void
    {
        // Given
        $object = RequestObjects::encryptedTo($this->encryption->publicJwk, RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())));
        $this->encryption->startRetiring($this->clock->now(), $this->clock->now());
        $this->encryption->retire($this->clock->now());

        // When / Then
        $this->refuses([
            'client_id' => 'jar-client',
            'request' => $object,
        ], 'invalid_request_object', 'The request object does not open with a key this provider publishes for encryption (RFC 9101 section 6.1).');
    }

    /**
     * RFC 7516 §4.1.6: the key is the one the header names, among those published for encryption; an
     * object encrypted to a key the tenant never published opens with nothing.
     */
    #[Test]
    public function anObjectEncryptedToAKeyTheTenantNeverPublishedIsRefused(): void
    {
        // Given
        /** @var array<string, mixed> $elsewhere */
        $elsewhere = [
            ...Algorithms::ecdhEsA256Kw()->generateKey()
                ->toPublic()
                ->all(),
            'alg' => Algorithms::ecdhEsA256Kw()->name(),
            'kid' => 'a-key-of-somebody-else',
        ];
        $object = RequestObjects::encryptedTo($elsewhere, RequestObjects::signed(RequestObjects::claims('jar-client', $this->tenant->issuer->value, $this->clock->now())));

        // When / Then
        $this->refuses([
            'client_id' => 'jar-client',
            'request' => $object,
        ], 'invalid_request_object', 'The request object does not open with a key this provider publishes for encryption (RFC 9101 section 6.1).');
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
