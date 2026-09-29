<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Exchange;

use Heidi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Exchange\PresentedAccessTokenType;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Exchange\MayAct;
use Heidi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\ClientAuthorization;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Tests\Fixture\AccessTokenShapes;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Secrets;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Heidi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8693 §3 "urn:ietf:params:oauth:token-type:access_token": an access token of this provider read as the
 * subject or the actor of an exchange, by the questions every resource of this provider asks of one.
 */
final class PresentedAccessTokenTypeTest extends TestCase
{
    private Tenant $tenant;

    private Client $client;

    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryAccessTokenRepository $tokens;

    private InMemoryClientRepository $clients;

    private PresentedAccessTokenType $type;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $user = Fixtures::user($this->tenant);
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), resources: Clients::resources());
        $this->session = Fixtures::session($user);
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->tokens = new InMemoryAccessTokenRepository();
        $sessions = new InMemoryAuthenticationSessionRepository();
        $sessions->save($this->session);
        $users = new InMemoryUserRepository();
        $users->save($user);
        $this->clients = new InMemoryClientRepository();
        $this->clients->save($this->client);
        $jwts = new Jwts($this->tenant);
        $this->type = new PresentedAccessTokenType(new AccessTokenInspector(
            AccessTokenShapes::verifier(
                new JwtLibraryJwsVerifier($jwts->keys, Algorithms::all()),
                $this->clients,
                $this->tokens,
                Subjects::publicKind(),
            ),
            $sessions,
            $this->grants,
            Subjects::ofAProvider($users),
        ));
    }

    #[Test]
    public function itAnswersToTheAccessTokenTypeOfTheRegistry(): void
    {
        // When / Then
        static::assertSame(TokenTypeIdentifier::ACCESS_TOKEN, $this->type->identifier()->value);
    }

    /**
     * RFC 8693 §2.1: what the exchange narrows is what the token says, read as every resource of this provider
     * reads it.
     */
    #[Test]
    public function itReadsWhatTheTokenSaysOfItsSubject(): void
    {
        // Given
        $token = $this->tokenOf($this->code());

        // When
        $presented = $this->type->read($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame('alice-subject', $presented->subject->value);
        static::assertSame($this->client, $presented->client);
        static::assertSame(['openid'], $presented->scopes->values());
        static::assertSame([Clients::CALENDAR], $presented->audience->values);
        static::assertTrue($presented->isAboutAUser());
    }

    /**
     * RFC 8693 §4.4: who may act for the subject of a token of this client, as its registration says it. One
     * place decides, and the claim the self-contained shape carries is written from it.
     */
    #[Test]
    public function itReadsWhoMayActForTheSubjectFromTheRegistrationOfTheClient(): void
    {
        // Given
        $holder = Clients::gateway(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            clientId: 'holder',
            mayAct: new MayAct(new Subject('gateway')),
        );
        $this->clients->save($holder);
        $token = $this->clientTokenOf($holder);

        // When
        $presented = $this->type->read($this->tenant, $token, Fixtures::now());

        // Then
        static::assertTrue($presented->mayAct?->equals(new MayAct(new Subject('gateway'))));
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself names that client and no sign-in, and the exchange reads
     * it as it reads any other.
     */
    #[Test]
    public function itReadsATokenOfAClientActingForItselfWithoutASignIn(): void
    {
        // Given
        $holder = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clients->save($holder);
        $token = $this->clientTokenOf($holder);

        // When
        $presented = $this->type->read($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame('batch', $presented->subject->value);
        static::assertFalse($presented->isAboutAUser());
    }

    /**
     * Architecture §4.6: a token the provider would refuse at its own resources is a token it refuses to
     * exchange, and what the caller is told is that the token is not good.
     */
    #[Test]
    public function itRefusesATokenOfASessionThatEnded(): void
    {
        // Given
        $token = $this->tokenOf($this->code());
        $this->session->end(SessionEnd::User, Fixtures::now()->modify('+1 minute'));

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The presented token is not one this provider honours (RFC 8693 section 2.2.2).');

        // When
        $this->type->read($this->tenant, $token, Fixtures::now()->modify('+2 minutes'));
    }

    #[Test]
    public function itRefusesWhatThisProviderNeverIssued(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The presented token is not one this provider honours (RFC 8693 section 2.2.2).');

        // When
        $this->type->read($this->tenant, 'not-a-token-of-this-provider', Fixtures::now());
    }

    private function code(): AuthorizationCode
    {
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), resources: ResourceIndicators::of([Clients::CALENDAR]));
        $this->grants->save($code);

        return $code;
    }

    private function tokenOf(AuthorizationCode $code): string
    {
        return $this->opaque()->issue(UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code), Fixtures::now())->value;
    }

    private function clientTokenOf(Client $client): string
    {
        return $this->opaque()->issue(
            new ClientAuthorization(
                Grants::clientCredentials(),
                Uuid::v7(),
                $client,
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Clients::CALENDAR]),
            ),
            Fixtures::now(),
        )->value;
    }

    private function opaque(): OpaqueAccessTokenIssuer
    {
        return new OpaqueAccessTokenIssuer($this->tokens, Secrets::drawer());
    }
}
