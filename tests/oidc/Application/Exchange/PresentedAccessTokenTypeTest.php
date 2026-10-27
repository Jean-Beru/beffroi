<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Exchange;

use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Exchange\PresentedAccessTokenType;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Tests\Fixture\AccessTokenShapes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Subjects;
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
            Subjects::personOfAToken($users),
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
     * Issue #588: the "sub" of the token is the name its first client holds (OIDC Core §8.1), so what the
     * exchange carries beside it is the person the inspection read it back as, and the acts of the token
     * it gets are written in the journal of that person.
     */
    #[Test]
    public function itReadsThePersonTheInspectionFoundBesideTheSubjectTheTokenNames(): void
    {
        // Given
        $token = $this->tokenOf($this->code());

        // When
        $presented = $this->type->read($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame('alice-subject', $presented->person?->value);
    }

    /**
     * RFC 6749 §4.4: there is nobody behind a token a client holds for itself, so there is nobody for the
     * exchange to write an act in the name of.
     */
    #[Test]
    public function itReadsNoPersonFromATokenOfAClientActingForItself(): void
    {
        // Given
        $holder = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clients->save($holder);
        $token = $this->clientTokenOf($holder);

        // When
        $presented = $this->type->read($this->tenant, $token, Fixtures::now());

        // Then
        static::assertNull($presented->person);
    }

    /**
     * Issue #831, RFC 7523 §2.1: a token issued on an assertion names the person the assertion was validated
     * for though nobody signed in for it here, so what the exchange gets for it names that person too, and
     * answers for them wherever it is presented in turn.
     */
    #[Test]
    public function itReadsThePersonATokenOfAnAssertionNames(): void
    {
        // Given
        $token = $this->tokenOfAnAssertion();

        // When
        $presented = $this->type->read($this->tenant, $token, Fixtures::now());

        // Then
        static::assertSame('alice-subject', $presented->person?->value);
    }

    /**
     * Issue #831: the token of an assertion whose person was disabled since is a token this provider refuses
     * at its own resources, so a service that kept it cannot turn it into a fresh one.
     */
    #[Test]
    public function itRefusesATokenOfAnAssertionWhosePersonWasDisabled(): void
    {
        // Given
        $token = $this->tokenOfAnAssertion();
        $this->session->user->disable(Fixtures::now());

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The presented token is not one this provider honours (RFC 8693 section 2.2.2).');

        // When
        $this->type->read($this->tenant, $token, Fixtures::now());
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
        return Tokens::accessToken($this->opaque(), UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code), Fixtures::now())->value;
    }

    private function clientTokenOf(Client $client): string
    {
        return Tokens::accessToken(
            $this->opaque(),
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

    /**
     * RFC 7523 §2.1: an opaque token of the job runner for the person an assertion named, whose record keeps
     * that person (issue #588) and no sign-in.
     */
    private function tokenOfAnAssertion(): string
    {
        $runner = Clients::presentingAssertions($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), accessTokenShape: Shapes::opaque());
        $this->clients->save($runner);
        $person = $this->session->user->subject;

        return Tokens::accessToken(
            $this->opaque(),
            new SubjectAuthorization(
                Grants::jwtBearer(),
                Uuid::v7(),
                $runner,
                $person,
                new Scopes([new Scope('invoices.read')]),
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Clients::CALENDAR]),
                ResourceIndicators::of([Clients::CALENDAR]),
                person: $person,
            ),
            Fixtures::now(),
        )->value;
    }

    private function opaque(): OpaqueAccessTokenIssuer
    {
        return new OpaqueAccessTokenIssuer($this->tokens, Secrets::drawer());
    }
}
