<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Authorization;

use function array_keys;
use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Heidi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientPresentation;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\ResponseFormat;
use Heidi\Oidc\Tests\Fixture\ClientEncryption;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Heidi\Oidc\Tests\Fixture\Shapes;

/**
 * JARM §2.1 and §2.4: what the provider signs for a client that asked for a signed answer, verified the
 * way that client verifies it, against the published JWK Set.
 */
final class ResponseDocumentIssuerTest extends TestCase
{
    private const array MANDATORY = ['iss', 'aud', 'exp'];

    private Tenant $tenant;

    private Jwts $jwts;

    private ResponseDocumentIssuer $issuer;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->jwts = new Jwts($this->tenant);
        $this->issuer = new ResponseDocumentIssuer($this->jwts->documents, new MockClock(Fixtures::now()));
    }

    /**
     * JARM §2.1: the parameters of the response, each one a claim, plus the issuer, the audience naming
     * the client and the expiry.
     */
    #[Test]
    public function theDocumentCarriesTheParametersOfTheAnswerAndTheThreeClaimsOfTheSection(): void
    {
        // Given
        $document = $this->issuer->issue($this->answer([
            'code' => 'the-code',
            'state' => 'state-of-the-client',
            'iss' => 'https://id.acme.example',
        ]));

        // When
        ['claims' => $claims] = $this->jwts->verify($document, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame(['code', 'state', 'iss', 'aud', 'exp'], array_keys($claims));
        static::assertSame('the-code', $claims['code']);
        static::assertSame('state-of-the-client', $claims['state']);
        static::assertSame('spa', $claims['aud']);
    }

    /**
     * JARM §2.1: the document expires, and soon, a response being read as the browser hands it over.
     */
    #[Test]
    public function theDocumentExpiresAfterTheLifetimeOfItsIssuer(): void
    {
        // Given
        $issuer = new ResponseDocumentIssuer($this->jwts->documents, new MockClock(Fixtures::now()), new DateInterval('PT2M'));
        $document = $issuer->issue($this->answer());

        // When
        ['claims' => $claims] = $this->jwts->verify($document, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame(Fixtures::now()->getTimestamp() + 120, $claims['exp']);
    }

    /**
     * The document is signed by the active key of the tenant, which is what the JWK Set publishes under
     * that "kid".
     */
    #[Test]
    public function theHeaderNamesTheActiveKeyOfTheTenant(): void
    {
        // Given
        $document = $this->issuer->issue($this->answer());

        // When
        ['header' => $header] = $this->jwts->verify($document, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame(
            [
                'alg' => 'RS256',
                'kid' => $this->jwts->key->kid,
            ],
            $header,
        );
    }

    /**
     * JARM §3: the algorithm is the one the client registered in "authorization_signed_response_alg".
     */
    #[Test]
    public function theDocumentIsSignedWithTheAlgorithmTheClientRegistered(): void
    {
        // Given
        $es256Key = $this->jwts->activate(Algorithms::es256());
        $client = new Client(
            $this->tenant,
            new ClientRegistration(
                'spa',
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                authorizationResponse: ResponseFormat::signed(Algorithms::es256()),
            ),
        );

        // When
        $document = $this->issuer->issue(new AuthorizationAnswer($client, new RedirectUri('https://spa.example/callback'), [
            'code' => 'the-code',
        ]));

        // Then
        ['header' => $header] = $this->jwts->verify($document, 'spa', Fixtures::now(), self::MANDATORY);
        static::assertSame(
            [
                'alg' => 'ES256',
                'kid' => $es256Key->kid,
            ],
            $header,
        );
    }

    /**
     * JARM §3 and issue #165: a client that registered an encryption receives the signed document inside
     * a JWE addressed to one of its keys, which is the same two steps as for an ID token.
     */
    #[Test]
    public function theDocumentIsEncryptedForAClientThatRegisteredOne(): void
    {
        // Given
        $client = Clients::encryptedFor($this->tenant, authorizationResponse: ResponseFormat::signed(null, ClientEncryption::registration()));

        // When
        $document = $this->issuer->issue(new AuthorizationAnswer($client, new RedirectUri('https://encrypted.example/callback'), [
            'code' => 'the-code',
        ]));

        // Then
        ['header' => $header, 'payload' => $signed] = ClientEncryption::open($document);
        static::assertSame('JWT', $header['cty']);
        static::assertSame(ClientEncryption::KEY_ID, $header['kid']);
        ['claims' => $claims] = $this->jwts->verify($signed, 'encrypted-client', Fixtures::now(), self::MANDATORY);
        static::assertSame('the-code', $claims['code']);
    }

    /**
     * JARM §2.4: a refusal is signed exactly as a code is, so a client that asked for a signed answer
     * never reads an unsigned one.
     */
    #[Test]
    public function aRefusalIsSignedTheSameWay(): void
    {
        // Given
        $document = $this->issuer->issue($this->answer([
            'error' => 'invalid_request',
            'error_description' => 'The code_challenge parameter is missing (RFC 7636 section 4.3).',
            'state' => 'state-of-the-client',
        ]));

        // When
        ['claims' => $claims] = $this->jwts->verify($document, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame('invalid_request', $claims['error']);
        static::assertSame('state-of-the-client', $claims['state']);
    }

    /**
     * @param non-empty-array<string, string> $parameters
     */
    private function answer(array $parameters = [
        'code' => 'the-code',
    ]): AuthorizationAnswer
    {
        return new AuthorizationAnswer(Clients::public($this->tenant), new RedirectUri('https://spa.example/callback'), $parameters);
    }
}
