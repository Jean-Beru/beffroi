<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use Beffroi\Core\Domain\Encoding\Base64Url;
use function str_repeat;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Core\Bridge\Uid\FixedUuidGenerator;
use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use function array_map;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Authorization\AuthenticationRequirement;
use Beffroi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Beffroi\Oidc\Application\Authorization\AuthorizationHandler;
use Beffroi\Oidc\Application\Consent\ConsentGranting;
use Beffroi\Oidc\Application\Consent\RequiredConsent;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Application\Claims\AssignedSubjectIdentifiers;
use Beffroi\Oidc\Application\Claims\ClaimsAskedByName;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPushedAuthorizationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Beffroi\Oidc\Domain\Interaction\ConsentRequired;
use Beffroi\Oidc\Domain\Interaction\ConsentRequirement;
use Beffroi\Oidc\Domain\Interaction\Granted;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequired;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\AccessDeniedException;
use Beffroi\Oidc\Exception\ConsentRequiredException;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LoginRequiredException;
use Beffroi\Oidc\Exception\UnmetAuthenticationRequirementsException;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeJwsVerifier;
use Beffroi\Oidc\Tests\Fixture\Logins;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Shapes;

final class AuthorizationHandlerTest extends TestCase
{
    private const string ALICE_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.YWxpY2U.c2lnbmF0dXJl';

    private const string BOB_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.Ym9i.c2lnbmF0dXJl';

    private const string FORGED_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.Zm9yZ2Vk.c2lnbmF0dXJl';

    private const string PAIRWISE_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.cGFpcndpc2U.c2lnbmF0dXJl';

    private Tenant $tenant;

    private User $alice;

    private User $bob;

    private Client $client;

    private Client $firstParty;

    private RequestContext $context;

    private MockClock $clock;

    private InMemoryInteractionRepository $interactions;

    private InMemoryConsentRepository $consents;

    private InMemoryAuthorizationCodeRepository $codes;

    private InMemoryPushedAuthorizationRecordRepository $pushedRequests;

    private InMemoryCredentialRepository $credentials;

    private RecordingEventDispatcher $events;

    private AssignedSubjectIdentifiers $subjects;

    private AuthorizationHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->firstParty = new Client(
            $this->tenant,
            new ClientRegistration(
                'portal',
                new ClientPresentation('Portal'),
                Methods::none(),
                false,
                [new RedirectUri('https://portal.acme.example/callback')],
                Shapes::jwt(),
                allowedScopes: new Scopes([Scope::openid(), new Scope('profile')]),
                requiresConsent: false,
            ),
        );
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now());
        $this->interactions = new InMemoryInteractionRepository();
        $this->consents = new InMemoryConsentRepository();
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->pushedRequests = new InMemoryPushedAuthorizationRecordRepository();
        $this->credentials = new InMemoryCredentialRepository();
        $this->credentials->save(Fixtures::password($this->alice));
        $this->events = new RecordingEventDispatcher();
        $this->bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $users = new InMemoryUserRepository();
        $users->save($this->alice);
        $users->save($this->bob);
        $this->subjects = Subjects::bothKinds($users);
        $jws = new FakeJwsVerifier();
        $jws->knows($this->tenant, self::ALICE_HINT, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"oidc-demo"}');
        $jws->knows($this->tenant, self::BOB_HINT, '{"iss":"https://id.acme.example","sub":"bob-subject","aud":"oidc-demo"}');
        $this->handler = $this->handlerWith(hints: new IdTokenHintVerifier($jws));
    }

    private function handlerWith(
        ?Logins $logins = null,
        ?IdTokenHintVerifier $hints = null,
        ?DateInterval $interactionLifetime = null,
        ?DateInterval $codeLifetime = null,
        ?SecretDrawer $secrets = null,
        ?UuidGeneratorInterface $uuids = null,
    ): AuthorizationHandler {
        $secrets ??= Secrets::drawer();
        $uuids ??= new SymfonyUuidGenerator();
        $claims = new ClaimsAskedByName(new StandardClaimsProvider());
        $codes = new AuthorizationCodeIssuer(
            $this->codes,
            $this->pushedRequests,
            $secrets,
            $uuids,
            $this->events,
            $claims,
            ...$codeLifetime === null ? [] : [$codeLifetime],
        );

        return new AuthorizationHandler(
            $this->interactions,
            new ConsentGranting($this->consents, $uuids, $this->events),
            new RequiredConsent($this->consents, $claims),
            $claims,
            $secrets,
            new AuthenticationRequirement(
                $logins ?? Logins::passwordAndPasskey(),
                $this->credentials,
                $hints ?? new IdTokenHintVerifier(new FakeJwsVerifier()),
                $this->subjects,
            ),
            $codes,
            $this->clock,
            ...$interactionLifetime === null ? [] : [$interactionLifetime],
        );
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function itRequiresALoginWhenThereIsNoSession(): void
    {
        // Given
        $request = $this->request();

        // When
        $decision = $this->handler->begin($request, null, $this->context, 'fr');

        // Then
        $login = $this->loginRequired($decision, LoginRequirement::NoSession);
        static::assertSame($request, $login->interaction->request);
        static::assertSame($this->tenant, $login->interaction->tenant);
        static::assertSame('fr', $login->interaction->locale);
        static::assertNull($login->interaction->session);
        static::assertFalse($login->interaction->isCompleted());
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function itParksTheInteractionForTenMinutes(): void
    {
        // When
        $decision = $this->handler->begin($this->request(), null, $this->context);

        // Then
        $interaction = $this->loginRequired($decision, LoginRequirement::NoSession)->interaction;
        static::assertEquals($this->clock->now(), $interaction->createdAt);
        static::assertEquals($this->clock->now()->modify('+10 minutes'), $interaction->expiresAt);
        static::assertSame($interaction, $this->interactions->find($interaction->id));
    }

    #[Test]
    public function itIssuesNothingBeforeTheLogin(): void
    {
        // When
        $this->handler->begin($this->request(), null, $this->context);

        // Then
        static::assertSame([], $this->events->events);
        static::assertSame([], $this->codes->all());
    }

    /**
     * @param callable(self): AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideInactiveSessions')]
    public function itRequiresALoginWhenTheSessionIsNotActive(callable $session): void
    {
        // Given
        $inactive = $session($this);

        // When
        $decision = $this->handler->begin($this->request(), $inactive, $this->context);

        // Then
        $login = $this->loginRequired($decision, LoginRequirement::NoSession);
        static::assertNull($login->interaction->session);
    }

    /**
     * @return iterable<string, array{callable(self): AuthenticationSession}>
     */
    public static function provideInactiveSessions(): iterable
    {
        yield 'ended' => [static function (self $test): AuthenticationSession {
            $session = $test->session();
            $session->end(SessionEnd::User, $test->clock->now());

            return $session;
        }];
        yield 'expired' => [
            static fn (self $test): AuthenticationSession => $test->session(Fixtures::now()->modify('-1 day')),
        ];
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function itRequiresAConsentWhenNoneCoversTheRequest(): void
    {
        // Given
        $session = $this->session();
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));
        $this->consents->save(
            new Consent(Uuid::v7(), $this->alice, Clients::public($this->tenant), new Scopes([Scope::openid(), new Scope('profile')]), Fixtures::now()),
        );

        // When
        $decision = $this->handler->begin($this->request(['openid', 'profile']), $session, $this->context);

        // Then
        $consent = $this->consentRequired($decision, ConsentRequirement::NotGranted);
        static::assertSame($session, $consent->session);
        static::assertEquals([Scope::openid(), new Scope('profile')], $consent->scopes->all);
    }

    #[Test]
    public function itParksTheInteractionWithTheSessionUntilTheConsent(): void
    {
        // Given
        $session = $this->session();

        // When
        $decision = $this->handler->begin($this->request(['openid', 'profile']), $session, $this->context);

        // Then
        $interaction = $this->consentRequired($decision, ConsentRequirement::NotGranted)->interaction;
        static::assertSame($session, $interaction->session);
        static::assertNull($interaction->consent);
        static::assertFalse($interaction->isCompleted());
        static::assertSame($interaction, $this->interactions->find($interaction->id));
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function itGrantsWhenAConsentInForceCoversTheRequest(): void
    {
        // Given
        $session = $this->session();
        $consent = new Consent(
            Uuid::v7(),
            $this->alice,
            $this->client,
            new Scopes([Scope::openid(), new Scope('profile'), new Scope('email')]),
            Fixtures::now(),
        );
        $this->consents->save($consent);

        // When
        $decision = $this->handler->begin($this->request(['openid', 'profile']), $session, $this->context);

        // Then
        $granted = $this->granted($decision);
        static::assertSame($consent, $granted->interaction->consent);
        static::assertSame($session, $granted->interaction->session);
        static::assertTrue($granted->interaction->isCompleted());
        static::assertSame($granted->interaction, $this->interactions->find($granted->interaction->id));
    }

    /**
     * Architecture §4.4
     */
    #[Test]
    public function theCodeIsIssuedForSixtySecondsWithTheAuthenticationAsItStands(): void
    {
        // Given
        $session = $this->session();
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('profile')]), Fixtures::now()));
        $request = $this->request(['openid', 'profile']);

        // When
        $decision = $this->handler->begin($request, $session, $this->context);

        // Then
        $granted = $this->granted($decision);
        $code = $granted->code;
        static::assertSame([$code], $this->codes->all());
        static::assertSame(DrawnSecret::digestOf($granted->response->code), $code->codeHash);
        static::assertSame($this->client, $code->client);
        static::assertSame($session, $code->session);
        static::assertSame($request->redirectUri, $code->redirectUri);
        static::assertSame($request->scopes, $code->scopes);
        static::assertSame('n-0S6_WzA2Mj', $code->nonce);
        static::assertSame($request->codeChallenge, $code->codeChallenge);
        static::assertNull($code->claimsRequest);
        static::assertEquals(Fixtures::now(), $code->authentication->authenticatedAt);
        static::assertSame(['pwd'], $code->authentication->methods);
        static::assertSame('1', $code->authentication->contextClass);
        static::assertEquals($this->clock->now(), $code->issuedAt);
        static::assertEquals($this->clock->now()->modify('+60 seconds'), $code->expiresAt);
    }

    /**
     * RFC 6749 §4.1.2, RFC 9207 §2
     */
    #[Test]
    public function theUserAgentGoesBackWithCodeStateAndIssuer(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(), $this->session(), $this->context);

        // Then
        $response = $this->granted($decision)->response;
        static::assertSame('https://id.acme.example', (string) $response->issuer);
        static::assertSame('af0ifjsldkj', $response->state);
        static::assertSame('https://demo.localhost/login/check', (string) $response->redirectUri);
        static::assertSame(
            [
                'code' => $response->code,
                'state' => 'af0ifjsldkj',
                'iss' => 'https://id.acme.example',
            ],
            $response->parameters(),
        );
    }

    #[Test]
    public function theCodeIssuedIsAnnouncedOnceWithTheRequestContext(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(), $this->session(), $this->context);

        // Then
        $issued = $this->events->of(AuthorizationCodeIssued::class);
        static::assertCount(1, $issued);
        static::assertCount(1, $this->events->events);
        static::assertSame($this->granted($decision)->code->codeHash, $issued[0]->codeHash);
        static::assertSame($this->context, $issued[0]->context);
        static::assertSame($this->tenant, $issued[0]->tenant);
        static::assertEquals($this->clock->now(), $issued[0]->occurredAt);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function itGrantsWithoutConsentToAFirstPartyClient(): void
    {
        // When
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, ['openid', 'profile']), $this->session(), $this->context);

        // Then
        $granted = $this->granted($decision);
        static::assertNull($granted->interaction->consent);
        static::assertSame([], $this->consents->all());
        static::assertSame($this->firstParty, $granted->code->client);
    }

    /**
     * OIDC Core §3.1.2.6
     */
    #[Test]
    public function itRefusesToPromptForALoginWhenPromptIsNone(): void
    {
        // When
        try {
            $this->handler->begin($this->request(prompts: [Prompt::None]), null, $this->context);
            static::fail('The request should have been refused.');
        } catch (LoginRequiredException $exception) {
            // Then
            static::assertSame('login_required', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('prompt=none', $exception->errorDescription);
        }
    }

    /**
     * OIDC Core §3.1.2.6
     */
    #[Test]
    public function theInteractionRefusedForPromptNoneIsOver(): void
    {
        // When
        try {
            $this->handler->begin($this->request(prompts: [Prompt::None]), null, $this->context);
        } catch (LoginRequiredException) {
        }

        // Then
        static::assertSame(1, $this->interactions->saves);
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * OIDC Core §3.1.2.6
     */
    #[Test]
    public function itRefusesToPromptForAConsentWhenPromptIsNone(): void
    {
        // Given
        $session = $this->session();

        // When
        try {
            $this->handler->begin($this->request(prompts: [Prompt::None]), $session, $this->context);
            static::fail('The request should have been refused.');
        } catch (ConsentRequiredException $exception) {
            // Then
            static::assertSame('consent_required', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('prompt=none', $exception->errorDescription);
        }
    }

    #[Test]
    public function theInteractionRefusedForPromptNoneWithASessionIsOver(): void
    {
        // Given
        $session = $this->session();

        // When
        try {
            $this->handler->begin($this->request(prompts: [Prompt::None]), $session, $this->context);
        } catch (ConsentRequiredException) {
        }

        // Then
        static::assertSame(1, $this->interactions->saves);
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itGrantsSilentlyWhenPromptIsNoneAndNothingIsMissing(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(prompts: [Prompt::None]), $this->session(), $this->context);

        // Then
        $this->granted($decision);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itRequiresAReauthenticationWhenPromptIsLogin(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(prompts: [Prompt::Login]), $this->session(), $this->context);

        // Then
        $this->loginRequired($decision, LoginRequirement::ReauthenticationRequested);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function aLoginDuringTheInteractionSatisfiesPromptLogin(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));
        $session = $this->session();
        $login = $this->loginRequired(
            $this->handler->begin($this->request(prompts: [Prompt::Login]), $session, $this->context),
            LoginRequirement::ReauthenticationRequested,
        );
        $this->clock->sleep(30);
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context($this->clock->now()));

        // When
        $decision = $this->handler->resume($login->interaction, $session, $this->context);

        // Then
        $granted = $this->granted($decision);
        static::assertEquals($this->clock->now(), $granted->code->authentication->authenticatedAt);
    }

    #[Test]
    public function aSessionEstablishedTheSecondTheInteractionBeganSatisfiesPromptLogin(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(prompts: [Prompt::Login]), $this->session($this->clock->now()), $this->context);

        // Then
        $this->granted($decision);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itRequiresAnAccountSelectionWhenPromptIsSelectAccount(): void
    {
        // When
        $decision = $this->handler->begin($this->request(prompts: [Prompt::SelectAccount]), $this->session(), $this->context);

        // Then
        $this->loginRequired($decision, LoginRequirement::AccountSelectionRequested);
    }

    /**
     * OIDC Core §3.1.2.1, architecture §4.3
     */
    #[Test]
    public function itRequiresAReauthenticationWhenTheLastOneIsOlderThanMaxAge(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(maxAge: 7199), $this->session(), $this->context);

        // Then
        $this->loginRequired($decision, LoginRequirement::MaxAgeExceeded);
    }

    #[Test]
    #[DataProvider('provideMaxAgesTheSessionMeets')]
    public function itGrantsWhenTheLastAuthenticationIsWithinMaxAge(int $maxAge): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(maxAge: $maxAge), $this->session(), $this->context);

        // Then
        $this->granted($decision);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideMaxAgesTheSessionMeets(): iterable
    {
        yield 'exactly two hours' => [7200];
        yield 'one day' => [86400];
    }

    #[Test]
    public function aLoginDuringTheInteractionSatisfiesMaxAge(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));
        $login = $this->loginRequired($this->handler->begin($this->request(maxAge: 0), null, $this->context), LoginRequirement::NoSession);
        $this->clock->sleep(5);
        $session = $this->session($this->clock->now());
        $this->clock->sleep(60);

        // When
        $decision = $this->handler->resume($login->interaction, $session, $this->context);

        // Then
        $this->granted($decision);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itGrantsWhenTheSessionIsTheUserOfTheIdTokenHint(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(idTokenHint: self::ALICE_HINT), $this->session(), $this->context);

        // Then
        $this->granted($decision);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itRequiresALoginWhenTheSessionIsNotTheUserOfTheIdTokenHint(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(idTokenHint: self::BOB_HINT), $this->session(), $this->context);

        // Then
        $this->loginRequired($decision, LoginRequirement::DifferentUser);
    }

    /**
     * OIDC Core §3.1.2.1, §8.1
     */
    #[Test]
    public function itGrantsWhenTheSessionIsTheUserOfTheIdTokenHintOfAPairwiseClient(): void
    {
        // Given
        $client = Clients::pairwise($this->tenant);
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $client, new Scopes([Scope::openid()]), Fixtures::now()));
        $handler = $this->handlerWith(hints: $this->hintOf($client, $this->subjects->resolve($this->alice, $client)));

        // When
        $decision = $handler->begin(Requests::authorization($client, idTokenHint: self::PAIRWISE_HINT), $this->session(), $this->context);

        // Then
        $this->granted($decision);
    }

    #[Test]
    public function itRequiresALoginWhenThereIsNoSessionForTheIdTokenHint(): void
    {
        // When
        $decision = $this->handler->begin($this->request(idTokenHint: self::BOB_HINT), null, $this->context);

        // Then
        $this->loginRequired($decision, LoginRequirement::NoSession);
    }

    /**
     * OIDC Core §3.1.2.1, §3.1.2.6
     *
     * @param callable(self): ?AuthenticationSession $held
     */
    #[Test]
    #[DataProvider('provideTheLoginPagesOfAHint')]
    public function aLoginDuringTheInteractionAsAnotherPersonThanTheHintNamesIsAnsweredLoginRequired(callable $held, LoginRequirement $asked): void
    {
        // Given
        $login = $this->loginRequired($this->handler->begin($this->request(idTokenHint: self::BOB_HINT), $held($this), $this->context), $asked);
        $this->clock->sleep(30);

        // When
        try {
            $this->handler->resume($login->interaction, $this->session($this->clock->now()), $this->context);
            static::fail('The request should have been refused.');
        } catch (LoginRequiredException $exception) {
            // Then
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('during this interaction', $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{callable(self): ?AuthenticationSession, LoginRequirement}>
     */
    public static function provideTheLoginPagesOfAHint(): iterable
    {
        yield 'no session' => [
            static fn (self $test): ?AuthenticationSession => null,
            LoginRequirement::NoSession,
        ];
        yield 'a session of another person' => [
            static fn (self $test): AuthenticationSession => $test->session(),
            LoginRequirement::DifferentUser,
        ];
    }

    /**
     * OIDC Core §3.1.2.6
     */
    #[Test]
    public function theInteractionAnsweredAfterALoginAsAnotherPersonIsOver(): void
    {
        // Given
        $login = $this->loginRequired($this->handler->begin($this->request(idTokenHint: self::BOB_HINT), null, $this->context), LoginRequirement::NoSession);
        $this->clock->sleep(30);

        // When
        try {
            $this->handler->resume($login->interaction, $this->session($this->clock->now()), $this->context);
        } catch (LoginRequiredException) {
        }

        // Then
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function aLoginDuringTheInteractionAsThePersonTheHintNamesGoesOn(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->bob, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));
        $login = $this->loginRequired(
            $this->handler->begin($this->request(idTokenHint: self::BOB_HINT), $this->session(), $this->context),
            LoginRequirement::DifferentUser,
        );
        $this->clock->sleep(30);
        $bob = Fixtures::session($this->bob, $this->clock->now());

        // When
        $decision = $this->handler->resume($login->interaction, $bob, $this->context);

        // Then
        static::assertSame($bob, $this->granted($decision)->code->session);
    }

    /**
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsOrNone')]
    public function itRefusesAForgedIdTokenHintBeforeAskingForALogin(callable $session): void
    {
        // Given
        $current = $session($this);

        // When
        try {
            $this->handler->begin($this->request(idTokenHint: self::FORGED_HINT), $current, $this->context);
            static::fail('The request should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('id_token_hint', $exception->errorDescription);
        }
    }

    /**
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsOrNone')]
    public function theInteractionRefusedForAForgedIdTokenHintIsOver(callable $session): void
    {
        // Given
        $current = $session($this);

        // When
        try {
            $this->handler->begin($this->request(idTokenHint: self::FORGED_HINT), $current, $this->context);
        } catch (InvalidRequestException) {
        }

        // Then
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * OIDC Core §3.1.2.1, §8
     *
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsOrNone')]
    public function theSubjectTheCoreKeepsInTheHintOfAPairwiseClientIsAnsweredLoginRequiredBeforeAnyPage(callable $session): void
    {
        // Given
        $client = Clients::pairwise($this->tenant);
        $handler = $this->handlerWith(hints: $this->hintOf($client, $this->alice->subject));

        // When
        try {
            $handler->begin(Requests::authorization($client, idTokenHint: self::PAIRWISE_HINT), $session($this), $this->context);
            static::fail('The request should have been refused.');
        } catch (LoginRequiredException $exception) {
            // Then
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('id_token_hint', $exception->errorDescription);
        }
    }

    /**
     * @param callable(self): ?AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsOrNone')]
    public function theInteractionAnsweredForAHintThatNamesNobodyIsOver(callable $session): void
    {
        // Given
        $client = Clients::pairwise($this->tenant);
        $handler = $this->handlerWith(hints: $this->hintOf($client, $this->alice->subject));

        // When
        try {
            $handler->begin(Requests::authorization($client, idTokenHint: self::PAIRWISE_HINT), $session($this), $this->context);
        } catch (LoginRequiredException) {
        }

        // Then
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * @return iterable<string, array{callable(self): ?AuthenticationSession}>
     */
    public static function provideSessionsOrNone(): iterable
    {
        yield 'no session' => [
            static fn (self $test): ?AuthenticationSession => null,
        ];
        yield 'a session' => [
            static fn (self $test): AuthenticationSession => $test->session(),
        ];
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function itResumesAfterTheLoginWithTheConsentStep(): void
    {
        // Given
        $login = $this->loginRequired($this->handler->begin($this->request(['openid', 'profile']), null, $this->context), LoginRequirement::NoSession);
        $this->clock->sleep(20);
        $session = $this->session($this->clock->now());
        $resumed = $this->interactions->find($login->interaction->id) ?? static::fail('The interaction should have been saved.');

        // When
        $decision = $this->handler->resume($resumed, $session, $this->context);

        // Then
        $consent = $this->consentRequired($decision, ConsentRequirement::NotGranted);
        static::assertSame($login->interaction, $consent->interaction);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function grantingTheConsentRecordsItForTheScopesOfTheRequest(): void
    {
        // Given
        $request = $this->request(['openid', 'profile']);
        $session = $this->session();
        $consent = $this->consentRequired($this->handler->begin($request, $session, $this->context), ConsentRequirement::NotGranted);
        $this->clock->sleep(20);

        // When
        $decision = $this->handler->grantConsent($consent->interaction, $session, Fixtures::context($this->clock->now()));

        // Then
        $recorded = $this->granted($decision)->interaction->consent ?? static::fail('The consent should have been recorded.');
        static::assertSame([$recorded], $this->consents->all());
        static::assertSame($recorded, $this->consents->findActive($this->alice, $this->client));
        static::assertSame($this->alice, $recorded->user);
        static::assertSame($this->client, $recorded->client);
        static::assertSame($request->scopes, $recorded->scopes);
        static::assertEquals($this->clock->now(), $recorded->grantedAt);
    }

    #[Test]
    public function whatItDrawsIsWhatItWasGiven(): void
    {
        // Given
        $ofTheInteraction = str_repeat("\x00", DrawnSecret::LENGTH);
        $ofTheCode = str_repeat("\x04", DrawnSecret::LENGTH);
        $consentId = Uuid::fromString('0199a0d4-0000-7000-8000-000000000042');
        $uuids = new FixedUuidGenerator([$consentId]);
        $handler = $this->handlerWith(
            secrets: new SecretDrawer(new FixedRandomness([$ofTheInteraction, $ofTheCode])),
            uuids: $uuids,
        );
        $session = $this->session();
        $consentRequired = $this->consentRequired(
            $handler->begin($this->request(['openid', 'profile']), $session, $this->context),
            ConsentRequirement::NotGranted,
        );

        // When
        $granted = $this->granted($handler->grantConsent($consentRequired->interaction, $session, $this->context));

        // Then
        static::assertSame(Base64Url::encode($ofTheInteraction), $granted->interaction->id);
        static::assertSame(Base64Url::encode($ofTheCode), $granted->response->code);
        static::assertTrue($consentId->equals($granted->interaction->consent?->id));
    }

    #[Test]
    public function grantingTheConsentAnnouncesItAndTheCodeWithTheRequestContext(): void
    {
        // Given
        $session = $this->session();
        $consent = $this->consentRequired(
            $this->handler->begin($this->request(['openid', 'profile']), $session, $this->context),
            ConsentRequirement::NotGranted,
        );
        $this->clock->sleep(20);
        $context = Fixtures::context($this->clock->now());

        // When
        $decision = $this->handler->grantConsent($consent->interaction, $session, $context);

        // Then
        $events = $this->events->of(ConsentGranted::class);
        static::assertCount(1, $events);
        $consentOfTheGrant = $this->granted($decision)->interaction->consent ?? static::fail('The grant carries the consent that was recorded.');
        static::assertSame($consentOfTheGrant->id, $events[0]->consentId);
        static::assertNull($events[0]->supersedes);
        static::assertSame($context, $events[0]->context);
        static::assertSame($this->tenant, $events[0]->tenant);
        static::assertEquals($this->clock->now(), $events[0]->occurredAt);
        static::assertCount(1, $this->events->of(AuthorizationCodeIssued::class));
        static::assertSame($context, $this->events->of(AuthorizationCodeIssued::class)[0]->context);
    }

    #[Test]
    public function itRecordsTheSessionItIsGivenTheConsentWith(): void
    {
        // Given
        $login = $this->loginRequired($this->handler->begin($this->request(), null, $this->context), LoginRequirement::NoSession);
        $session = $this->session($this->clock->now());

        // When
        $decision = $this->handler->grantConsent($login->interaction, $session, $this->context);

        // Then
        $granted = $this->granted($decision);
        static::assertSame($session, $granted->interaction->session);
        static::assertSame($session, $granted->code->session);
    }

    #[Test]
    public function aNewConsentAddsTheScopesOfTheRequestToThePreviousOnes(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('email')]), Fixtures::now()));
        $consent = $this->consentRequired(
            $this->handler->begin($this->request(['openid', 'profile']), $this->session(), $this->context),
            ConsentRequirement::NotGranted,
        );

        // When
        $decision = $this->handler->grantConsent($consent->interaction, $consent->session, $this->context);

        // Then
        $recorded = $this->granted($decision)->interaction->consent ?? static::fail('The consent should have been recorded.');
        static::assertEquals([Scope::openid(), new Scope('email'), new Scope('profile')], $recorded->scopes->all);
    }

    #[Test]
    public function aNewConsentRevokesThePreviousOne(): void
    {
        // Given
        $previous = new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('email')]), Fixtures::now());
        $this->consents->save($previous);
        $consent = $this->consentRequired(
            $this->handler->begin($this->request(['openid', 'profile']), $this->session(), $this->context),
            ConsentRequirement::NotGranted,
        );

        // When
        $decision = $this->handler->grantConsent($consent->interaction, $consent->session, $this->context);

        // Then
        static::assertFalse($previous->isActive());
        static::assertEquals($this->clock->now(), $previous->revokedAt);
        static::assertSame($this->granted($decision)->interaction->consent, $this->consents->findActive($this->alice, $this->client));
        static::assertCount(2, $this->consents->all());
        static::assertSame(3, $this->consents->saves, 'the previous consent is saved revoked, then the new one');
    }

    #[Test]
    public function aNewConsentIsAnnouncedWithTheOneItSupersedes(): void
    {
        // Given
        $previous = new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('email')]), Fixtures::now());
        $this->consents->save($previous);
        $consent = $this->consentRequired(
            $this->handler->begin($this->request(['openid', 'profile']), $this->session(), $this->context),
            ConsentRequirement::NotGranted,
        );

        // When
        $this->handler->grantConsent($consent->interaction, $consent->session, $this->context);

        // Then
        static::assertSame($previous->id, $this->events->of(ConsentGranted::class)[0]->supersedes);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itAsksAgainWhenPromptIsConsent(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('profile')]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(prompts: [Prompt::Consent]), $this->session(), $this->context);

        // Then
        $this->consentRequired($decision, ConsentRequirement::ConsentRequested);
    }

    #[Test]
    public function aResumeWithoutAnAnswerAsksAgainWhenPromptIsConsent(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('profile')]), Fixtures::now()));
        $session = $this->session();
        $consent = $this->consentRequired(
            $this->handler->begin($this->request(prompts: [Prompt::Consent]), $session, $this->context),
            ConsentRequirement::ConsentRequested,
        );

        // When
        $decision = $this->handler->resume($consent->interaction, $session, $this->context);

        // Then
        $this->consentRequired($decision, ConsentRequirement::ConsentRequested);
    }

    #[Test]
    public function theConsentGivenDuringTheInteractionSatisfiesPromptConsent(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('profile')]), Fixtures::now()));
        $session = $this->session();
        $consent = $this->consentRequired(
            $this->handler->begin($this->request(prompts: [Prompt::Consent]), $session, $this->context),
            ConsentRequirement::ConsentRequested,
        );

        // When
        $decision = $this->handler->grantConsent($consent->interaction, $session, $this->context);

        // Then
        $this->granted($decision);
    }

    #[Test]
    public function itRequiresALoginWhenTheSessionEndedBeforeTheConsent(): void
    {
        // Given
        $session = $this->session();
        $consent = $this->consentRequired($this->handler->begin($this->request(), $session, $this->context), ConsentRequirement::NotGranted);
        $session->end(SessionEnd::User, $this->clock->now());

        // When
        $decision = $this->handler->grantConsent($consent->interaction, $session, $this->context);

        // Then
        $this->loginRequired($decision, LoginRequirement::NoSession);
    }

    #[Test]
    public function itRecordsNoConsentWithoutAnActiveSession(): void
    {
        // Given
        $session = $this->session();
        $consent = $this->consentRequired($this->handler->begin($this->request(), $session, $this->context), ConsentRequirement::NotGranted);
        $session->end(SessionEnd::User, $this->clock->now());

        // When
        $this->handler->grantConsent($consent->interaction, $session, $this->context);

        // Then
        static::assertSame([], $this->consents->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function itAsksAgainWhenTheConsentInForceDoesNotCoverTheDetailsAsked(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));
        $request = Requests::authorization($this->client, authorizationDetails: AuthorizationDetailTypes::details());

        // When
        $decision = $this->handler->begin($request, $this->session(), $this->context);

        // Then
        $this->consentRequired($decision, ConsentRequirement::NotGranted);
    }

    #[Test]
    public function itAsksNothingWhenTheConsentInForceCoversTheDetailsAsked(): void
    {
        // Given
        $this->consents->save(new Consent(
            Uuid::v7(),
            $this->alice,
            $this->client,
            new Scopes([Scope::openid()]),
            Fixtures::now(),
            AuthorizationDetailTypes::details(),
        ));
        $request = Requests::authorization($this->client, authorizationDetails: AuthorizationDetailTypes::details());

        // When
        $decision = $this->handler->begin($request, $this->session(), $this->context);

        // Then
        $this->granted($decision);
    }

    #[Test]
    public function theConsentPageCarriesTheDetailsTheRequestAsksFor(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details();
        $request = Requests::authorization($this->client, authorizationDetails: $details);

        // When
        $decision = $this->handler->begin($request, $this->session(), $this->context);

        // Then
        static::assertSame($details, $this->consentRequired($decision, ConsentRequirement::NotGranted)->authorizationDetails);
    }

    /**
     * Architecture §4.3, RFC 9396 §2
     */
    #[Test]
    public function grantingTheConsentRecordsTheDetailsAndTheCodeCarriesThem(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details();
        $session = $this->session();
        $consent = $this->consentRequired(
            $this->handler->begin(Requests::authorization($this->client, authorizationDetails: $details), $session, $this->context),
            ConsentRequirement::NotGranted,
        );

        // When
        $granted = $this->granted($this->handler->grantConsent($consent->interaction, $session, $this->context));

        // Then
        static::assertTrue($this->consents->all()[0]->authorizationDetails?->equals($details));
        static::assertTrue($granted->code->authorizationDetails?->equals($details));
    }

    /**
     * OIDC Core §3.1.2.4, §5.5
     */
    #[Test]
    public function itAsksAgainWhenTheConsentInForceDoesNotCoverAClaimAskedForByName(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(claims: '{"userinfo": {"email": null}}'), $this->session(), $this->context);

        // Then
        $this->consentRequired($decision, ConsentRequirement::NotGranted);
    }

    /**
     * OIDC Core §5.4, §5.5
     */
    #[Test]
    public function itAsksNothingWhenTheConsentInForceHoldsTheScopeOfAClaimAskedForByName(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid(), new Scope('email')]), Fixtures::now()));

        // When
        $decision = $this->handler->begin($this->request(claims: '{"userinfo": {"email": null}}'), $this->session(), $this->context);

        // Then
        $this->granted($decision);
    }

    /**
     * OIDC Core §3.1.2.4
     */
    #[Test]
    public function theConsentPageCarriesTheClaimsAskedForByNameBeyondTheScopesOfTheRequest(): void
    {
        // Given
        $request = $this->request(['openid', 'email'], claims: '{"userinfo": {"email": null, "phone_number": null}, "id_token": {"name": null}}');

        // When
        $decision = $this->handler->begin($request, $this->session(), $this->context);

        // Then
        static::assertSame(['name'], $this->consentRequired($decision, ConsentRequirement::NotGranted)->claims->all);
    }

    /**
     * Architecture §4.3, OIDC Core §5.5
     */
    #[Test]
    public function grantingTheConsentRecordsTheClaimsAskedForByNameAndTheCodeCarriesThem(): void
    {
        // Given
        $session = $this->session();
        $consent = $this->consentRequired(
            $this->handler->begin($this->request(claims: '{"userinfo": {"email": null}}'), $session, $this->context),
            ConsentRequirement::NotGranted,
        );

        // When
        $granted = $this->granted($this->handler->grantConsent($consent->interaction, $session, $this->context));

        // Then
        static::assertSame(['email'], $this->consents->all()[0]->claims->all);
        static::assertSame(['email'], $granted->code->claimsRequest?->claimNames()->all);
    }

    /**
     * RFC 7591 §2, OIDC Core §5.5.1
     */
    #[Test]
    public function theCodeCarriesNoClaimAskedForByNameBeyondTheScopesTheClientRegistered(): void
    {
        // Given
        $request = Requests::authorization(
            $this->firstParty,
            claims: ClaimsRequest::fromJson('{"userinfo": {"name": null, "email": null}, "id_token": {"phone_number": null}}'),
        );

        // When
        $decision = $this->handler->begin($request, $this->session(), $this->context);

        // Then
        $code = $this->granted($decision)->code;
        static::assertEquals(['name' => new ClaimRequest()], $code->claimsRequest?->userinfo);
        static::assertSame([], $code->claimsRequest?->idToken);
    }

    /**
     * RFC 6749 §4.1.2.1
     */
    #[Test]
    public function itDeniesWhenTheUserRefuses(): void
    {
        // Given
        $consent = $this->consentRequired($this->handler->begin($this->request(), $this->session(), $this->context), ConsentRequirement::NotGranted);

        // When
        try {
            $this->handler->deny($consent->interaction);
        } catch (AccessDeniedException $exception) {
            // Then
            static::assertSame('access_denied', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertSame('The end user denied the request.', $exception->errorDescription);
        }
    }

    /**
     * RFC 6749 §4.1.2.1
     */
    #[Test]
    public function theInteractionDeniedIsOverAndRecordsNothing(): void
    {
        // Given
        $consent = $this->consentRequired($this->handler->begin($this->request(), $this->session(), $this->context), ConsentRequirement::NotGranted);

        // When
        try {
            $this->handler->deny($consent->interaction);
        } catch (AccessDeniedException) {
        }

        // Then
        static::assertTrue($consent->interaction->isCompleted());
        static::assertSame(2, $this->interactions->saves, 'saved when parked, saved again completed');
        static::assertSame([], $this->consents->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * @param callable(self, Interaction, AuthenticationSession, AuthenticationSession): mixed $resume
     */
    #[Test]
    #[DataProvider('provideResumptions')]
    public function itDoesNotResumeACompletedInteraction(callable $resume): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));
        $session = $this->session();
        $granted = $this->granted($this->handler->begin($this->request(), $session, $this->context));
        $ended = $this->session();
        $ended->end(SessionEnd::User, $this->clock->now());

        // When
        try {
            $resume($this, $granted->interaction, $session, $ended);
            static::fail('The interaction should have been refused.');
        } catch (InteractionCompletedException $exception) {
            // Then
            static::assertSame($granted->interaction->id, $exception->interactionId);
        }
    }

    #[Test]
    public function aCompletedInteractionIssuesNoSecondCode(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));
        $session = $this->session();
        $granted = $this->granted($this->handler->begin($this->request(), $session, $this->context));

        // When
        try {
            $this->handler->grantConsent($granted->interaction, $session, $this->context);
        } catch (InteractionCompletedException) {
        }

        // Then
        static::assertCount(1, $this->codes->all());
    }

    /**
     * @param callable(self, Interaction, AuthenticationSession, AuthenticationSession): mixed $resume
     */
    #[Test]
    #[DataProvider('provideResumptions')]
    public function itDoesNotResumeAnExpiredInteraction(callable $resume): void
    {
        // Given
        $login = $this->loginRequired($this->handler->begin($this->request(), null, $this->context), LoginRequirement::NoSession);
        $this->clock->sleep(600);
        $session = $this->session($this->clock->now());
        $ended = $this->session($this->clock->now());
        $ended->end(SessionEnd::User, $this->clock->now());

        // When
        try {
            $resume($this, $login->interaction, $session, $ended);
            static::fail('The interaction should have been refused.');
        } catch (InteractionExpiredException $exception) {
            // Then
            static::assertSame($login->interaction->id, $exception->interactionId);
        }
    }

    #[Test]
    public function anExpiredInteractionStaysUncompleted(): void
    {
        // Given
        $login = $this->loginRequired($this->handler->begin($this->request(), null, $this->context), LoginRequirement::NoSession);
        $this->clock->sleep(600);

        // When
        try {
            $this->handler->grantConsent($login->interaction, $this->session($this->clock->now()), $this->context);
        } catch (InteractionExpiredException) {
        }

        // Then
        static::assertFalse($login->interaction->isCompleted());
    }

    /**
     * @return iterable<string, array{callable(self, Interaction, AuthenticationSession, AuthenticationSession): mixed}>
     */
    public static function provideResumptions(): iterable
    {
        yield 'resume with a session' => [
            static fn (self $test, Interaction $interaction, AuthenticationSession $session, AuthenticationSession $ended) => $test->handler->resume(
                $interaction,
                $session,
                $test->context,
            ),
        ];
        yield 'resume without a session' => [
            static fn (self $test, Interaction $interaction, AuthenticationSession $session, AuthenticationSession $ended) => $test->handler->resume(
                $interaction,
                null,
                $test->context,
            ),
        ];
        yield 'grant the consent' => [
            static fn (self $test, Interaction $interaction, AuthenticationSession $session, AuthenticationSession $ended) => $test->handler->grantConsent(
                $interaction,
                $session,
                $test->context,
            ),
        ];
        yield 'grant the consent with an ended session' => [
            static fn (self $test, Interaction $interaction, AuthenticationSession $session, AuthenticationSession $ended) => $test->handler->grantConsent(
                $interaction,
                $ended,
                $test->context,
            ),
        ];
        yield 'deny' => [
            static fn (
                self $test,
                Interaction $interaction,
                AuthenticationSession $session,
                AuthenticationSession $ended,
            ) => $test->handler->deny($interaction),
        ];
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function theCodeCarriesTheRequestedClassTheSessionSatisfies(): void
    {
        // Given
        $session = $this->session();
        $session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context(Fixtures::now()));

        // When
        $decision = $this->handler->begin(
            Requests::authorization($this->firstParty, claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["phrh", "1"]}}}')),
            $session,
            $this->context,
        );

        // Then
        static::assertSame('1', $this->granted($decision)->code->authentication->contextClass);
    }

    /**
     * OIDC Core §5.5.1.1, decision 0010
     */
    #[Test]
    public function aVoluntaryRequestNamingNoClassOfTheTenantIsAnsweredWithTheCurrentClass(): void
    {
        // When
        $decision = $this->handler->begin(
            Requests::authorization(
                $this->firstParty,
                acrValues: ['urn:mace:incommon:iap:silver', 'http://schemas.openid.net/pape/policies/2007/06/multi-factor'],
            ),
            $this->session(),
            $this->context,
        );

        // Then
        static::assertSame('1', $this->granted($decision)->code->authentication->contextClass);
    }

    /**
     * OIDC Core §5.5.1.1, OIDC Core Error Code unmet_authentication_requirements §1
     */
    #[Test]
    public function anEssentialAcrTheProviderCannotAssertFailsBeforeTheLogin(): void
    {
        // When
        try {
            $this->handler->begin(
                $this->request(claims: '{"id_token": {"acr": {"essential": true, "values": ["urn:mace:incommon:iap:silver", "3"]}}}'),
                null,
                $this->context,
            );
            static::fail('The request should have been refused.');
        } catch (UnmetAuthenticationRequirementsException $exception) {
            // Then
            static::assertSame('unmet_authentication_requirements', $exception->error);
            static::assertSame(400, $exception->statusCode);
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('acr_values_supported', $exception->errorDescription);
        }
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function anEssentialAcrNoLoginCanProveFailsBeforeTheLogin(): void
    {
        // Given
        $handler = $this->handlerWith(Logins::passwordOnly());

        // Then
        $this->expectException(UnmetAuthenticationRequirementsException::class);

        // When
        $handler->begin($this->request(claims: '{"id_token": {"acr": {"essential": true, "values": ["phr", "2"]}}}'), $this->session(), $this->context);
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function aVoluntaryAcrNoLoginCanProveIsAnsweredWithTheCurrentClass(): void
    {
        // Given
        $handler = $this->handlerWith(Logins::passwordOnly());

        // When
        $decision = $handler->begin(Requests::authorization($this->firstParty, acrValues: ['phr']), $this->session(), $this->context);

        // Then
        static::assertSame('1', $this->granted($decision)->code->authentication->contextClass);
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function anEssentialAcrTheProviderCannotAssertFailsWhateverTheSessionAndThePrompt(): void
    {
        // Given
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, new Scopes([Scope::openid()]), Fixtures::now()));

        // Then
        $this->expectException(UnmetAuthenticationRequirementsException::class);

        // When
        $this->handler->begin(
            $this->request(prompts: [Prompt::None], claims: '{"id_token": {"acr": {"essential": true, "value": "urn:mace:incommon:iap:silver"}}}'),
            $this->session(),
            $this->context,
        );
    }

    #[Test]
    public function theInteractionRefusedForAnUnmetAcrIsOver(): void
    {
        // When
        try {
            $this->handler->begin(
                $this->request(claims: '{"id_token": {"acr": {"essential": true, "values": ["urn:mace:incommon:iap:silver"]}}}'),
                null,
                $this->context,
            );
        } catch (UnmetAuthenticationRequirementsException) {
        }

        // Then
        static::assertSame(1, $this->interactions->saves);
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    #[DataProvider('provideEssentialAcrRequestsTheProviderMeets')]
    public function anEssentialAcrTheProviderAssertsAsksForTheLogin(string $claims): void
    {
        // When
        $decision = $this->handler->begin($this->request(claims: $claims), null, $this->context);

        // Then
        $this->loginRequired($decision, LoginRequirement::NoSession);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEssentialAcrRequestsTheProviderMeets(): iterable
    {
        yield 'the single factor' => ['{"id_token": {"acr": {"essential": true, "values": ["1"]}}}'];
        yield 'the single factor after a class the provider does not assert' => [
            '{"id_token": {"acr": {"essential": true, "values": ["urn:mace:incommon:iap:silver", "1"]}}}',
        ];
        yield 'a passkey class' => ['{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}'];
        yield 'essential without a value' => ['{"id_token": {"acr": {"essential": true}}}'];
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function aVoluntaryAcrTheProviderCannotAssertAsksForTheLogin(): void
    {
        // When
        $decision = $this->handler->begin(
            $this->request(acrValues: ['phrh'], claims: '{"id_token": {"acr": {"values": ["urn:mace:incommon:iap:silver"]}}}'),
            null,
            $this->context,
        );

        // Then
        $this->loginRequired($decision, LoginRequirement::NoSession);
    }

    /**
     * Decision 0010
     */
    #[Test]
    #[DataProvider('provideStepUpRequests')]
    public function aPasswordSessionAskedForAPasskeyClassIsSentToTheLoginForTheMissingFactor(AuthorizationRequest $request): void
    {
        // Given
        $passkey = $this->aliceHoldsAPasskey();

        // When
        $decision = $this->handler->begin($request, $this->session(), $this->context);

        // Then
        $login = $this->loginRequired($decision, LoginRequirement::StrongerFactorRequired);
        static::assertNotNull($login->stepUp);
        static::assertSame(['phr'], array_map(static fn (AuthenticationContextClass $class): string => $class->value, $login->stepUp->classes));
        static::assertSame(['pwd'], $login->stepUp->proofs->methodReferences());
        static::assertSame([$passkey], $login->stepUp->credentials);
        static::assertSame(1, $this->interactions->saves);
        static::assertFalse($this->savedInteraction()->isCompleted());
    }

    /**
     * @return iterable<string, array{AuthorizationRequest}>
     */
    public static function provideStepUpRequests(): iterable
    {
        $tenant = Fixtures::tenant();
        $client = new Client(
            $tenant,
            new ClientRegistration(
                'portal',
                new ClientPresentation('Portal'),
                Methods::none(),
                false,
                [new RedirectUri('https://portal.acme.example/callback')],
                Shapes::jwt(),
                allowedScopes: new Scopes([Scope::openid(), new Scope('profile')]),
                requiresConsent: false,
            ),
        );
        yield 'essential, the claims parameter' => [Requests::authorization(
            $client,
            claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}'),
        )];
        yield 'voluntary, acr_values' => [Requests::authorization($client, acrValues: ['phr'])];
        yield 'after a class the tenant does not name' => [Requests::authorization($client, acrValues: ['urn:mace:incommon:iap:silver', 'phr'])];
        yield 'with prompt=login, as the re-authentication of Symfony sends it' => [Requests::authorization(
            $client,
            prompts: [Prompt::Login],
            acrValues: ['phr'],
        )];
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function theStepUpSaysWhichLoginWouldSatisfyTheClient(): void
    {
        // Given
        $this->aliceHoldsAPasskey();

        // When
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, acrValues: ['phrh', '2']), $this->session(), $this->context);

        // Then
        $stepUp = $this->loginRequired($decision, LoginRequirement::StrongerFactorRequired)->stepUp;
        static::assertNotNull($stepUp);
        static::assertSame(['phrh', '2'], array_map(static fn (AuthenticationContextClass $class): string => $class->value, $stepUp->classes));
        static::assertTrue($stepUp->wouldBeMetBy([new AuthenticationMethod('hwk'), new AuthenticationMethod('user')]));
        static::assertFalse($stepUp->wouldBeMetBy([AuthenticationMethod::password()]));
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function aPasskeySessionAskedForTwoFactorsIsSatisfiedByAPassword(): void
    {
        // Given
        $session = Fixtures::session($this->alice, proofs: AuthenticationProofs::ofAll([
            new AuthenticationMethod('hwk'),
            new AuthenticationMethod('user'),
        ], Fixtures::now()));

        // When
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, acrValues: ['2']), $session, $this->context);

        // Then
        $stepUp = $this->loginRequired($decision, LoginRequirement::StrongerFactorRequired)->stepUp;
        static::assertNotNull($stepUp);
        static::assertTrue($stepUp->wouldBeMetBy([AuthenticationMethod::password()]));
    }

    /**
     * OIDC Core §3.1.2.6
     */
    #[Test]
    public function promptNoneWithAStepUpIsLoginRequired(): void
    {
        // Given
        $this->aliceHoldsAPasskey();

        // Then
        $this->expectException(LoginRequiredException::class);

        // When
        $this->handler->begin(Requests::authorization($this->firstParty, prompts: [Prompt::None], acrValues: ['phr']), $this->session(), $this->context);
    }

    #[Test]
    public function aSessionSatisfyingARequestedClassGetsTheCodeAtOnce(): void
    {
        // Given
        $session = Fixtures::session($this->alice, proofs: AuthenticationProofs::ofAll([
            AuthenticationMethod::password(),
            new AuthenticationMethod('hwk'),
            new AuthenticationMethod('user'),
        ], Fixtures::now()));

        // When
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, acrValues: ['phr']), $session, $this->context);

        // Then
        static::assertSame('phr', $this->granted($decision)->code->authentication->contextClass);
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function thePasskeyProvenOnTheSessionDuringTheStepUpSatisfiesTheRequest(): void
    {
        // Given
        $this->aliceHoldsAPasskey();
        $session = $this->session();
        $interaction = $this->loginRequired(
            $this->handler->begin(
                Requests::authorization($this->firstParty, claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}')),
                $session,
                $this->context,
            ),
            LoginRequirement::StrongerFactorRequired,
        )->interaction;
        $this->clock->sleep(30);
        $session->recordProof(new AuthenticationMethod('hwk'), Fixtures::context($this->clock->now()));
        $session->recordProof(new AuthenticationMethod('user'), Fixtures::context($this->clock->now()));

        // When
        $decision = $this->handler->resume($interaction, $session, $this->context);

        // Then
        $code = $this->granted($decision)->code;
        static::assertSame('phr', $code->authentication->contextClass);
        static::assertSame(['pwd', 'hwk', 'user', 'mfa'], $code->authentication->methods);
        static::assertEquals($this->clock->now(), $code->authentication->authenticatedAt);
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function anEssentialClassStillUnsatisfiedAfterTheLoginIsRefused(): void
    {
        // Given
        $this->aliceHoldsAPasskey();
        $session = $this->session();
        $interaction = $this->loginRequired(
            $this->handler->begin(
                Requests::authorization($this->firstParty, claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}')),
                $session,
                $this->context,
            ),
            LoginRequirement::StrongerFactorRequired,
        )->interaction;
        $this->clock->sleep(30);
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context($this->clock->now()));

        // When
        try {
            $this->handler->resume($interaction, $session, $this->context);
            static::fail('The request should have been refused.');
        } catch (UnmetAuthenticationRequirementsException $exception) {
            // Then
            static::assertSame('unmet_authentication_requirements', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertTrue($interaction->isCompleted());
        }
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function aVoluntaryClassStillUnsatisfiedAfterTheLoginIsAnsweredWithTheCurrentClass(): void
    {
        // Given
        $this->aliceHoldsAPasskey();
        $session = $this->session();
        $interaction = $this->loginRequired(
            $this->handler->begin(Requests::authorization($this->firstParty, acrValues: ['phr']), $session, $this->context),
            LoginRequirement::StrongerFactorRequired,
        )->interaction;
        $this->clock->sleep(30);
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context($this->clock->now()));

        // When
        $decision = $this->handler->resume($interaction, $session, $this->context);

        // Then
        static::assertSame('1', $this->granted($decision)->code->authentication->contextClass);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function anEssentialAcrNoCredentialOfTheUserCanProveFailsBeforeThePage(): void
    {
        // When
        try {
            $this->handler->begin(
                Requests::authorization($this->firstParty, claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}')),
                $this->session(),
                $this->context,
            );
            static::fail('The request should have been refused.');
        } catch (UnmetAuthenticationRequirementsException $exception) {
            // Then
            static::assertSame('unmet_authentication_requirements', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertSame('The end user holds no credential able to satisfy any requested acr value.', $exception->errorDescription);
            static::assertSame(1, $this->interactions->saves);
            static::assertTrue($this->savedInteraction()->isCompleted());
        }
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function anEssentialAcrNoCredentialOfTheUserCanProveFailsBeforeThePagePromptLoginAsksFor(): void
    {
        // Then
        $this->expectException(UnmetAuthenticationRequirementsException::class);

        // When
        $this->handler->begin(
            Requests::authorization(
                $this->firstParty,
                prompts: [Prompt::Login],
                claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}'),
            ),
            $this->session(),
            $this->context,
        );
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function aVoluntaryAcrNoCredentialOfTheUserCanProveIsAnsweredAtOnceWithTheCurrentClass(): void
    {
        // When
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, acrValues: ['phr']), $this->session(), $this->context);

        // Then
        static::assertSame('1', $this->granted($decision)->code->authentication->contextClass);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function aVoluntaryAcrNoCredentialOfTheUserCanProveLeavesThePromptLoginAPlainReauthentication(): void
    {
        // When
        $decision = $this->handler->begin(
            Requests::authorization($this->firstParty, prompts: [Prompt::Login], acrValues: ['phr']),
            $this->session(),
            $this->context,
        );

        // Then
        $login = $this->loginRequired($decision, LoginRequirement::ReauthenticationRequested);
        static::assertNull($login->stepUp);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function aRevokedPasskeyOfTheUserCountsForNothing(): void
    {
        // Given
        $this->aliceHoldsAPasskey()->revoke($this->clock->now());

        // Then
        $this->expectException(UnmetAuthenticationRequirementsException::class);

        // When
        $this->handler->begin(
            Requests::authorization($this->firstParty, claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}')),
            $this->session(),
            $this->context,
        );
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function theStepUpKeepsTheClassesACredentialOfTheUserReaches(): void
    {
        // Given
        $this->aliceHoldsAPasskey(synced: true);

        // When
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, acrValues: ['phrh', 'phr']), $this->session(), $this->context);

        // Then
        $stepUp = $this->loginRequired($decision, LoginRequirement::StrongerFactorRequired)->stepUp;
        static::assertNotNull($stepUp);
        static::assertSame(['phr'], array_map(static fn (AuthenticationContextClass $class): string => $class->value, $stepUp->classes));
    }

    #[Test]
    public function aPasswordSessionWithATotpAskedForTwoFactorsIsSentToTheLoginForTheCode(): void
    {
        // Given
        $totp = Totps::credential($this->alice, new FakePasswordHasher());
        $this->credentials->save($totp);

        // When
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, acrValues: ['2']), $this->session(), $this->context);

        // Then
        $stepUp = $this->loginRequired($decision, LoginRequirement::StrongerFactorRequired)->stepUp;
        static::assertNotNull($stepUp);
        static::assertSame([$totp], $stepUp->credentials);
        static::assertSame(['totp'], $stepUp->kinds());
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function theInteractionLifetimeIsConfigurable(): void
    {
        // Given
        $handler = $this->handlerWith(interactionLifetime: new DateInterval('PT5M'), codeLifetime: new DateInterval('PT30S'));

        // When
        $decision = $handler->begin(Requests::authorization($this->firstParty), $this->session(), $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('+5 minutes'), $this->granted($decision)->interaction->expiresAt);
    }

    /**
     * Architecture §4.4
     */
    #[Test]
    public function theCodeLifetimeIsConfigurable(): void
    {
        // Given
        $handler = $this->handlerWith(interactionLifetime: new DateInterval('PT5M'), codeLifetime: new DateInterval('PT30S'));

        // When
        $decision = $handler->begin(Requests::authorization($this->firstParty), $this->session(), $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('+30 seconds'), $this->granted($decision)->code->expiresAt);
    }

    /**
     * @param list<string> $scopes
     * @param list<Prompt> $prompts
     * @param list<string> $acrValues
     */
    private function request(
        array $scopes = ['openid'],
        array $prompts = [],
        ?int $maxAge = null,
        ?string $idTokenHint = null,
        array $acrValues = [],
        ?string $claims = null,
    ): AuthorizationRequest {
        return Requests::authorization(
            $this->client,
            $scopes,
            $prompts,
            $maxAge,
            $idTokenHint,
            claims: $claims === null ? null : ClaimsRequest::fromJson($claims),
            acrValues: $acrValues,
        );
    }

    private function hintOf(Client $client, Subject $subject): IdTokenHintVerifier
    {
        $jws = new FakeJwsVerifier();
        $jws->knows($this->tenant, self::PAIRWISE_HINT, json_encode([
            'iss' => 'https://id.acme.example',
            'sub' => $subject->value,
            'aud' => $client->registration->clientId,
        ], JSON_THROW_ON_ERROR));

        return new IdTokenHintVerifier($jws);
    }

    private function session(?DateTimeImmutable $authenticatedAt = null): AuthenticationSession
    {
        return Fixtures::session($this->alice, $authenticatedAt);
    }

    private function aliceHoldsAPasskey(bool $synced = false): PasskeyCredential
    {
        $passkey = Fixtures::passkey($this->alice, backupEligible: $synced, backedUp: $synced);
        $this->credentials->save($passkey);

        return $passkey;
    }

    private function loginRequired(AuthorizationDecision $decision, LoginRequirement $requirement): LoginRequired
    {
        static::assertInstanceOf(LoginRequired::class, $decision);
        static::assertSame($requirement, $decision->requirement);

        return $decision;
    }

    private function consentRequired(AuthorizationDecision $decision, ConsentRequirement $requirement): ConsentRequired
    {
        static::assertInstanceOf(ConsentRequired::class, $decision);
        static::assertSame($requirement, $decision->requirement);

        return $decision;
    }

    private function granted(AuthorizationDecision $decision): Granted
    {
        static::assertInstanceOf(Granted::class, $decision);

        return $decision;
    }

    private function savedInteraction(): Interaction
    {
        return $this->interactions->last() ?? static::fail('An interaction should have been saved.');
    }
}
