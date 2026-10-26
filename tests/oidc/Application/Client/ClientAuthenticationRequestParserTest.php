<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequestParser;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\RecordingCompactJwtReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What arrived at an endpoint that authenticates a client, read into the request the methods are handed
 * (RFC 6749 §2.3): the credentials it carries are strings, and the assertion of RFC 7523 §2.2 is read
 * here and nowhere else.
 */
final class ClientAuthenticationRequestParserTest extends TestCase
{
    private const string ENDPOINT = 'https://id.acme.example/token';

    private Tenant $tenant;

    private RequestContext $context;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
    }

    #[Test]
    public function itCarriesWhatTheRequestCarries(): void
    {
        // When
        $request = $this->read([
            'client_id' => 'a-client',
        ], 'Basic abc');

        // Then
        static::assertSame($this->tenant, $request->tenant);
        static::assertSame(self::ENDPOINT, $request->endpoint);
        static::assertSame('Basic abc', $request->authorizationHeader);
        static::assertSame($this->context, $request->context);
        static::assertSame('a-client', $request->clientId());
        static::assertNull($request->certificate);
    }

    /**
     * RFC 6749 appendix A: an empty parameter is no parameter, and an empty credential is no credential.
     */
    #[Test]
    public function anEmptyParameterIsNoParameter(): void
    {
        // When
        $request = $this->read([
            'client_id' => '',
            'client_assertion' => '',
            'client_assertion_type' => '',
        ]);

        // Then
        static::assertNull($request->clientId());
        static::assertNull($request->assertion);
    }

    /**
     * RFC 6749 §2.3.1: an empty secret is a secret all the same, presented and wrong, and is read as it
     * is given.
     */
    #[Test]
    public function anEmptySecretIsASecret(): void
    {
        // When
        $request = $this->read([
            'client_secret' => '',
        ]);

        // Then
        static::assertSame('', $request->secret());
    }

    #[Test]
    public function aRequestWithoutAnAssertionCarriesNone(): void
    {
        // When
        $request = $this->read([
            'client_id' => 'a-client',
        ]);

        // Then
        static::assertNull($request->assertion);
    }

    /**
     * RFC 7523 §2.2: the assertion is read and verified in nothing, so that the provider knows which
     * client claims it and which key is supposed to have signed it.
     */
    #[Test]
    public function itReadsTheAssertionTheRequestCarries(): void
    {
        // Given
        $assertion = $this->assertion();

        // When
        $request = $this->read(ClientAssertions::parameters($assertion));

        // Then
        static::assertNotNull($request->assertion);
        static::assertSame($assertion, $request->assertion->compact);
        static::assertSame('ES256', $request->assertion->algorithm());
        static::assertSame('a-client', $request->assertion->claim('sub'));
    }

    /**
     * The assertion is read once, whatever reads it afterwards: the parser is what owns the reader, and
     * every method the authenticator then asks is handed what was read here.
     */
    #[Test]
    public function itReadsTheAssertionOnce(): void
    {
        // Given
        $reader = new RecordingCompactJwtReader();
        $assertion = $this->assertion();

        // When
        $request = Methods::requestParser($reader)->read(
            $this->tenant,
            self::ENDPOINT,
            null,
            ClientAssertions::parameters($assertion),
            $this->context,
            null,
        );

        // Then
        static::assertSame([$assertion], $reader->read);
        static::assertNotNull($request->assertion);
    }

    /**
     * RFC 7523 §2.2: a request that carries one half of the pair carries neither.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideHalfOfThePair')]
    public function itRefusesHalfOfThePair(array $parameters): void
    {
        // When
        $failure = $this->failToRead($parameters);

        // Then
        static::assertSame(ClientAuthenticationFailureReason::MalformedCredentials, $failure->reason);
        static::assertTrue($failure->malformedRequest);
        static::assertSame(
            'The client_assertion and client_assertion_type parameters go together (RFC 7523 section 2.2).',
            $failure->description,
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideHalfOfThePair(): iterable
    {
        yield 'an assertion without its type' => [[
            'client_assertion' => 'an.assertion.here',
        ]];
        yield 'a type without its assertion' => [[
            'client_assertion_type' => ClientAuthenticationRequestParser::ASSERTION_TYPE,
        ]];
    }

    /**
     * RFC 7523 §2.2: "client_assertion_type" has one value.
     */
    #[Test]
    public function itRefusesATypeThatIsNotTheOneOfTheSpecification(): void
    {
        // When
        $failure = $this->failToRead([
            'client_assertion' => 'an.assertion.here',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer',
        ]);

        // Then
        static::assertSame(ClientAuthenticationFailureReason::MalformedCredentials, $failure->reason);
        static::assertSame(
            'The client_assertion_type parameter must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer (RFC 7523 section 2.2).',
            $failure->description,
        );
    }

    #[Test]
    public function itRefusesAnAssertionItCannotRead(): void
    {
        // When
        $failure = $this->failToRead(ClientAssertions::parameters('not-a-jwt'));

        // Then
        static::assertSame(ClientAuthenticationFailureReason::MalformedCredentials, $failure->reason);
        static::assertSame('The client assertion is not a readable JWT (RFC 7523 section 2.2).', $failure->description);
    }

    /**
     * The audit trail is told which client the body named, that being all a request whose assertion
     * cannot be read says about itself.
     */
    #[Test]
    public function aRefusedAssertionNamesTheClientOfTheBody(): void
    {
        // When
        $failure = $this->failToRead([
            'client_id' => 'a-client',
            ...ClientAssertions::parameters('not-a-jwt'),
        ]);

        // Then
        static::assertSame('a-client', $failure->clientId);
    }

    /**
     * A request whose credentials are not strings is refused before anything is read, and the audit trail
     * keeps no identifier from it, because none of it can be trusted.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('provideCredentialsThatAreNotStrings')]
    public function itRefusesACredentialThatIsNotAString(array $parameters, string $description): void
    {
        // When
        $failure = $this->failToRead($parameters);

        // Then
        static::assertSame(ClientAuthenticationFailureReason::MalformedCredentials, $failure->reason);
        static::assertTrue($failure->malformedRequest);
        static::assertSame($description, $failure->description);
        static::assertNull($failure->clientId);
        static::assertNull($failure->method);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideCredentialsThatAreNotStrings(): iterable
    {
        yield 'client_id repeated' => [
            [
                'client_id' => ['a-client'],
            ],
            'The client_id parameter must be a string.',
        ];
        yield 'client_secret repeated' => [
            [
                'client_secret' => ['a-secret'],
            ],
            'The client_secret parameter must be a string.',
        ];
        yield 'client_assertion repeated' => [
            [
                'client_assertion' => ['an.assertion.here'],
            ],
            'The client_assertion parameter must be a string.',
        ];
        yield 'client_assertion_type repeated' => [
            [
                'client_assertion_type' => [ClientAuthenticationRequestParser::ASSERTION_TYPE],
            ],
            'The client_assertion_type parameter must be a string.',
        ];
    }

    /**
     * A parameter that is not a credential is not this parser's business: what reads it says what it
     * takes, and an authorization request carries parameters of every shape (RFC 8707 §2).
     */
    #[Test]
    public function itLeavesAParameterThatIsNotACredentialAlone(): void
    {
        // When
        $request = $this->read([
            'resource' => ['https://api.acme.example', 'https://other.acme.example'],
        ]);

        // Then
        static::assertNull($request->parameter('resource'));
    }

    private function assertion(): string
    {
        return ClientAssertions::signedWithKey(
            ClientAssertions::claims('a-client', $this->tenant->issuer->value, $this->context->receivedAt),
        );
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function read(array $parameters, ?string $authorizationHeader = null): ClientAuthenticationRequest
    {
        return Methods::requestParser()->read($this->tenant, self::ENDPOINT, $authorizationHeader, $parameters, $this->context, null);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function failToRead(array $parameters): ClientAuthenticationFailure
    {
        try {
            $this->read($parameters);
        } catch (ClientAuthenticationFailure $failure) {
            return $failure;
        }
        static::fail('The request should not have been read.');
    }
}
