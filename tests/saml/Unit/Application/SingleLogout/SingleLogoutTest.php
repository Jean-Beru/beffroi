<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\SingleLogout;

use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Saml\Application\SingleLogout\SingleLogout;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\FixedSalt;
use Beffroi\Saml\Tests\Fixture\GivenSignOutRequests;
use Beffroi\Saml\Tests\Fixture\RecordingSignOutResponder;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignOutRequests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.5 steps 2 to 4: the sessions a logout request accepted names, ended when their user is the
 * principal it names, as every session of the core ends, and the answer written with the status that says so.
 */
final class SingleLogoutTest extends TestCase
{
    private const string IDENTITY_PROVIDER = 'https://id.acme.example' . FixedEndpoints::METADATA;

    private Tenant $tenant;

    private MockClock $clock;

    private InMemoryAuthenticationSessionRepository $sessions;

    private RecordingEventDispatcher $events;

    private RecordingSignOutResponder $responder;

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock(Fixtures::now());
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->events = new RecordingEventDispatcher();
        $this->responder = new RecordingSignOutResponder();
        $this->session = Fixtures::session(Fixtures::user($this->tenant));
        $this->sessions->save($this->session);
    }

    /**
     * S-24, S-25: the session the request names, of the principal it names, ends, by the service provider of the
     * request, which the core says with the context of the request.
     */
    #[Test]
    public function theSessionOfThePrincipalEnds(): void
    {
        // When
        $this->singleLogout($this->request())->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertEquals(
            [new AuthenticationSessionEnded($this->session, Fixtures::now(), Fixtures::context())],
            $this->events->of(AuthenticationSessionEnded::class),
        );
    }

    /**
     * S-25: by a relying party, as the end session endpoint of OpenID Connect ends one.
     */
    #[Test]
    public function theSessionEndsByARelyingParty(): void
    {
        // When
        $this->singleLogout($this->request())->post($this->tenant, ['SAMLRequest' => 'given'], Fixtures::context());

        // Then
        static::assertSame(SessionEnd::RelyingParty, $this->session->endedBy);
    }

    /**
     * S-24, S-27, section 6.5 step 4: the answer is written from the request, Success, issued by the identity provider
     * of the tenant at the instant of the clock, and is what the browser carries back.
     */
    #[Test]
    public function theAnswerSaysSuccess(): void
    {
        // Given
        $request = $this->request();

        // When
        $answer = $this->singleLogout($request)->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertEquals(
            [
                new SignOutResponse(self::IDENTITY_PROVIDER, $request, SignOutStatus::Success, Fixtures::now()),
                new RedirectedMessage(SignOutRequests::SINGLE_LOGOUT . '?SAMLResponse=answered'),
            ],
            [$this->responder->response, $answer],
        );
    }

    /**
     * S-24: the NameID qualified by the two entities, as the assertion carried it, is the principal's.
     */
    #[Test]
    public function aNameIdQualifiedByTheTwoEntitiesIsThePrincipals(): void
    {
        // Given
        $request = $this->request(nameQualifier: self::IDENTITY_PROVIDER, spNameQualifier: ServiceProviderDocuments::SIGNED);

        // When
        $this->singleLogout($request)->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertSame(SignOutStatus::Success, $this->responder->response?->status);
    }

    /**
     * S-24: a session ended already, a session of another tenant, a session index that names no session and one that
     * is no UUID, are ended already: Success, and nothing ends.
     */
    #[Test]
    #[DataProvider('provideSessionsEndedAlready')]
    public function aSessionThatIsNotActiveIsEndedAlready(string $case): void
    {
        // Given
        $sessionIndexes = match ($case) {
            'ended' => $this->ended(),
            'of another tenant' => $this->ofAnotherTenant(),
            'unknown' => [Uuid::v7()->toRfc4122()],
            default => ['_session-1'],
        };

        // When
        $this->singleLogout($this->request(sessionIndexes: $sessionIndexes))->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertSame(
            [SignOutStatus::Success, []],
            [$this->responder->response?->status, $this->events->of(AuthenticationSessionEnded::class)],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSessionsEndedAlready(): iterable
    {
        yield 'a session ended already' => ['ended'];
        yield 'a session of another tenant' => ['of another tenant'];
        yield 'an ID no session carries' => ['unknown'];
        yield 'a session index that is no UUID' => ['no UUID'];
    }

    /**
     * S-24: a NameID that is not the principal of the session named, by its value, its format or a qualifier of
     * another entity, ends nothing and is answered UnknownPrincipal.
     */
    #[Test]
    #[DataProvider('provideOtherPrincipals')]
    public function anotherPrincipalEndsNothing(
        ?string $nameId,
        string $format,
        ?string $nameQualifier,
        ?string $spNameQualifier,
    ): void {
        // Given
        $request = $this->request($nameId, $format, $nameQualifier, $spNameQualifier);

        // When
        $this->singleLogout($request)->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertSame(
            [SignOutStatus::UnknownPrincipal, false],
            [$this->responder->response?->status, $this->session->hasEnded()],
        );
    }

    /**
     * @return iterable<string, array{?string, string, ?string, ?string}>
     */
    public static function provideOtherPrincipals(): iterable
    {
        yield 'the identifier of another user' => ['another-users-identifier', PersistentNameId::FORMAT, null, null];
        yield 'the identifier of the user in another format' => [null, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', null, null];
        yield 'qualified by another identity provider' => [null, PersistentNameId::FORMAT, 'https://other.example/saml/metadata', null];
        yield 'qualified by another service provider' => [null, PersistentNameId::FORMAT, null, 'https://other.example.org/saml'];
    }

    /**
     * S-24: when one session named is of another principal, none of the sessions named ends.
     */
    #[Test]
    public function oneSessionOfAnotherPrincipalEndsNone(): void
    {
        // Given
        $other = Fixtures::session(Fixtures::user($this->tenant, 'bob', 'bob-subject'));
        $this->sessions->save($other);
        $request = $this->request(sessionIndexes: [$this->session->id->toRfc4122(), $other->id->toRfc4122()]);

        // When
        $this->singleLogout($request)->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertSame(
            [SignOutStatus::UnknownPrincipal, false, false],
            [$this->responder->response?->status, $this->session->hasEnded(), $other->hasEnded()],
        );
    }

    /**
     * S-24, Core §3.7.3.2: a request naming no session index is not supported here (section 12); nothing ends.
     */
    #[Test]
    public function aRequestNamingNoSessionIsUnsupported(): void
    {
        // When
        $this->singleLogout($this->request(sessionIndexes: []))->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertSame(
            [SignOutStatus::RequestUnsupported, false],
            [$this->responder->response?->status, $this->session->hasEnded()],
        );
    }

    /**
     * S-24: every session named of the principal ends, each once.
     */
    #[Test]
    public function everySessionNamedEnds(): void
    {
        // Given
        $second = Fixtures::session($this->session->user);
        $this->sessions->save($second);
        $request = $this->request(sessionIndexes: [$this->session->id->toRfc4122(), $second->id->toRfc4122()]);

        // When
        $this->singleLogout($request)->redirect($this->tenant, 'SAMLRequest=given', Fixtures::context());

        // Then
        static::assertSame([true, true], [$this->session->hasEnded(), $second->hasEnded()]);
    }

    /**
     * The request of the service provider of the fixtures for the session of setUp(), its NameID the one S-13
     * computes for the user of that session unless the test says otherwise.
     *
     * @param list<string>|null $sessionIndexes
     */
    private function request(
        ?string $nameId = null,
        string $format = PersistentNameId::FORMAT,
        ?string $nameQualifier = null,
        ?string $spNameQualifier = null,
        ?array $sessionIndexes = null,
    ): SignOutRequest {
        return SignOutRequests::request(
            $nameId ?? PersistentNameId::derive(ServiceProviderDocuments::SIGNED, $this->session->user->subject, FixedSalt::SALT)->value,
            $sessionIndexes ?? [$this->session->id->toRfc4122()],
            $format,
            $nameQualifier,
            $spNameQualifier,
        );
    }

    /**
     * @return list<string>
     */
    private function ended(): array
    {
        $this->session->end(SessionEnd::User, Fixtures::now());

        return [$this->session->id->toRfc4122()];
    }

    /**
     * @return list<string>
     */
    private function ofAnotherTenant(): array
    {
        $session = Fixtures::session(Fixtures::user(Fixtures::tenant('globex', 'https://id.globex.example')));
        $this->sessions->save($session);

        return [$session->id->toRfc4122()];
    }

    private function singleLogout(SignOutRequest $received): SingleLogout
    {
        return new SingleLogout(
            new GivenSignOutRequests($received),
            $this->responder,
            $this->sessions,
            new SessionTerminator($this->sessions, $this->clock, $this->events),
            new FixedSalt(),
            new FixedEndpoints(),
            $this->clock,
        );
    }
}
