<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Authorization\AuthorizationHandler;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Heidi\Oidc\Domain\Event\ConsentGranted;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\ConsentRequired;
use Heidi\Oidc\Domain\Interaction\ConsentRequirement;
use Heidi\Oidc\Domain\Interaction\Granted;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Interaction\LoginRequired;
use Heidi\Oidc\Domain\Interaction\LoginRequirement;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\AccessDeniedException;
use Heidi\Oidc\Exception\ConsentRequiredException;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\LoginRequiredException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeJwsVerifier;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class AuthorizationHandlerTest extends TestCase
{
    private const string ALICE_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.YWxpY2U.c2lnbmF0dXJl';

    private const string BOB_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.Ym9i.c2lnbmF0dXJl';

    private const string FORGED_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.Zm9yZ2Vk.c2lnbmF0dXJl';

    private Tenant $tenant;

    private User $alice;

    private Client $client;

    private Client $firstParty;

    private RequestContext $context;

    private MockClock $clock;

    private InMemoryInteractionRepository $interactions;

    private InMemoryConsentRepository $consents;

    private InMemoryAuthorizationCodeRepository $codes;

    private RecordingEventDispatcher $events;

    private AuthorizationHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->firstParty = new Client($this->tenant, 'portal', 'Portal', TokenEndpointAuthMethod::None, null, [new RedirectUri('https://portal.acme.example/callback')], allowedScopes: [Scope::openid(), new Scope('profile')], requiresConsent: false);
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $this->context = Fixtures::context($this->clock->now());
        $this->interactions = new InMemoryInteractionRepository();
        $this->consents = new InMemoryConsentRepository();
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $this->events = new RecordingEventDispatcher();
        $jws = new FakeJwsVerifier();
        $jws->knows($this->tenant, self::ALICE_HINT, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"oidc-demo"}');
        $jws->knows($this->tenant, self::BOB_HINT, '{"iss":"https://id.acme.example","sub":"bob-subject","aud":"oidc-demo"}');
        $this->handler = new AuthorizationHandler($this->interactions, $this->consents, $this->codes, new IdTokenHintVerifier($jws), $this->clock, $this->events);
    }

    /**
     * Architecture §4.3: no session, the user logs in first. The interaction is parked for ten minutes
     * with the request and the locale the integration chose.
     */
    #[Test]
    public function itRequiresALoginWhenThereIsNoSession(): void
    {
        $request = $this->request();

        $decision = $this->handler->begin($request, null, $this->context, 'fr');

        $login = $this->loginRequired($decision, LoginRequirement::NoSession);
        static::assertSame($request, $login->interaction->request);
        static::assertSame($this->tenant, $login->interaction->tenant);
        static::assertSame('fr', $login->interaction->locale);
        static::assertNull($login->interaction->session);
        static::assertEquals($this->clock->now(), $login->interaction->createdAt);
        static::assertEquals($this->clock->now()->modify('+10 minutes'), $login->interaction->expiresAt);
        static::assertFalse($login->interaction->isCompleted());
        static::assertSame($login->interaction, $this->interactions->find($login->interaction->id));
        static::assertSame([], $this->events->events);
        static::assertSame([], $this->codes->all());
    }

    /**
     * A session that ended, or that expired, is no session.
     */
    #[Test]
    public function itRequiresALoginWhenTheSessionIsNotActive(): void
    {
        $ended = $this->session();
        $ended->end(SessionEnd::User, $this->clock->now());
        $expired = $this->session(Fixtures::now()->modify('-1 day'));

        foreach ([$ended, $expired] as $session) {
            $decision = $this->handler->begin($this->request(), $session, $this->context);

            $login = $this->loginRequired($decision, LoginRequirement::NoSession);
            static::assertNull($login->interaction->session);
        }
    }

    /**
     * Architecture §4.3: a session, but no consent covering the scopes of the request for this client.
     */
    #[Test]
    public function itRequiresAConsentWhenNoneCoversTheRequest(): void
    {
        $session = $this->session();
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid()], Fixtures::now()));
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, Clients::public($this->tenant), [Scope::openid(), new Scope('profile')], Fixtures::now()));

        $decision = $this->handler->begin($this->request(['openid', 'profile']), $session, $this->context);

        $consent = $this->consentRequired($decision, ConsentRequirement::NotGranted);
        static::assertSame($session, $consent->session);
        static::assertSame($session, $consent->interaction->session);
        static::assertNull($consent->interaction->consent);
        static::assertEquals([Scope::openid(), new Scope('profile')], $consent->scopes);
        static::assertFalse($consent->interaction->isCompleted());
        static::assertSame($consent->interaction, $this->interactions->find($consent->interaction->id));
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.3 and §4.4: everything acquired, the code is issued for sixty seconds, stored as
     * its hash with the authentication as it stands, and the user agent goes back with code, state and
     * iss (RFC 9207 §2). The interaction is over.
     */
    #[Test]
    public function itGrantsWhenAConsentInForceCoversTheRequest(): void
    {
        $session = $this->session();
        $consent = new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid(), new Scope('profile'), new Scope('email')], Fixtures::now());
        $this->consents->save($consent);
        $request = $this->request(['openid', 'profile']);

        $decision = $this->handler->begin($request, $session, $this->context);

        $granted = $this->granted($decision);
        static::assertSame($consent, $granted->interaction->consent);
        static::assertSame($session, $granted->interaction->session);
        static::assertTrue($granted->interaction->isCompleted());
        static::assertSame($granted->interaction, $this->interactions->find($granted->interaction->id));

        $code = $granted->code;
        static::assertSame([$code], $this->codes->all());
        static::assertSame(AuthorizationCode::hash($granted->response->code), $code->codeHash);
        static::assertSame($this->client, $code->client);
        static::assertSame($session, $code->session);
        static::assertSame($request->redirectUri, $code->redirectUri);
        static::assertSame($request->scopes, $code->scopes);
        static::assertSame('n-0S6_WzA2Mj', $code->nonce);
        static::assertSame($request->codeChallenge, $code->codeChallenge);
        static::assertNull($code->claimsRequest);
        static::assertEquals(Fixtures::now(), $code->authenticatedAt);
        static::assertSame(['pwd'], $code->authenticationMethods);
        static::assertNull($code->authenticationContextClass);
        static::assertEquals($this->clock->now(), $code->issuedAt);
        static::assertEquals($this->clock->now()->modify('+60 seconds'), $code->expiresAt);

        static::assertSame('https://id.acme.example', (string) $granted->response->issuer);
        static::assertSame('af0ifjsldkj', $granted->response->state);
        static::assertSame(sprintf('https://demo.localhost/login/check?code=%s&state=af0ifjsldkj&iss=https%%3A%%2F%%2Fid.acme.example', $granted->response->code), $granted->response->toUri());

        $issued = $this->events->of(AuthorizationCodeIssued::class);
        static::assertCount(1, $issued);
        static::assertSame($code, $issued[0]->code);
        static::assertSame($this->context, $issued[0]->context);
        static::assertSame($this->tenant, $issued[0]->tenant);
        static::assertEquals($this->clock->now(), $issued[0]->occurredAt);
        static::assertCount(1, $this->events->events);
    }

    /**
     * Architecture §4.3: a client with requiresConsent = false skips the consent step; nothing is looked
     * up and nothing is recorded.
     */
    #[Test]
    public function itGrantsWithoutConsentToAFirstPartyClient(): void
    {
        $decision = $this->handler->begin(Requests::authorization($this->firstParty, ['openid', 'profile']), $this->session(), $this->context);

        $granted = $this->granted($decision);
        static::assertNull($granted->interaction->consent);
        static::assertSame([], $this->consents->all());
        static::assertSame($this->firstParty, $granted->code->client);
    }

    /**
     * OIDC Core §3.1.2.6: with prompt=none, a login that would be needed is the redirected error
     * login_required, and the interaction is over.
     */
    #[Test]
    public function itRefusesToPromptForALoginWhenPromptIsNone(): void
    {
        try {
            $this->handler->begin($this->request(prompts: [Prompt::None]), null, $this->context);
            static::fail('The request should have been refused.');
        } catch (LoginRequiredException $exception) {
            static::assertSame('login_required', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('prompt=none', $exception->errorDescription);
        }
        static::assertSame(1, $this->interactions->saves);
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * OIDC Core §3.1.2.6: with prompt=none, a consent that would be needed is the redirected error
     * consent_required, and the interaction is over.
     */
    #[Test]
    public function itRefusesToPromptForAConsentWhenPromptIsNone(): void
    {
        try {
            $this->handler->begin($this->request(prompts: [Prompt::None]), $this->session(), $this->context);
            static::fail('The request should have been refused.');
        } catch (ConsentRequiredException $exception) {
            static::assertSame('consent_required', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertStringContainsString('prompt=none', $exception->errorDescription);
        }
        static::assertSame(1, $this->interactions->saves);
        static::assertTrue($this->savedInteraction()->isCompleted());
    }

    /**
     * OIDC Core §3.1.2.1: prompt=none with everything in place is a silent grant.
     */
    #[Test]
    public function itGrantsSilentlyWhenPromptIsNoneAndNothingIsMissing(): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid()], Fixtures::now()));

        $decision = $this->handler->begin($this->request(prompts: [Prompt::None]), $this->session(), $this->context);

        $this->granted($decision);
    }

    /**
     * OIDC Core §3.1.2.1 prompt=login: the user re-authenticates even with a session; a login done during
     * the interaction satisfies it on resume.
     */
    #[Test]
    public function itRequiresAReauthenticationWhenPromptIsLogin(): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid()], Fixtures::now()));
        $session = $this->session();

        $decision = $this->handler->begin($this->request(prompts: [Prompt::Login]), $session, $this->context);
        $login = $this->loginRequired($decision, LoginRequirement::ReauthenticationRequested);

        $this->clock->sleep(30);
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context($this->clock->now()));
        $granted = $this->granted($this->handler->resume($login->interaction, $session, $this->context));
        static::assertEquals($this->clock->now(), $granted->code->authenticatedAt);

        // a session established the very second the interaction began was established during it
        $this->granted($this->handler->begin($this->request(prompts: [Prompt::Login]), $this->session($this->clock->now()), $this->context));
    }

    /**
     * OIDC Core §3.1.2.1 prompt=select_account: the user chooses an account, which the login page does.
     */
    #[Test]
    public function itRequiresAnAccountSelectionWhenPromptIsSelectAccount(): void
    {
        $decision = $this->handler->begin($this->request(prompts: [Prompt::SelectAccount]), $this->session(), $this->context);

        $this->loginRequired($decision, LoginRequirement::AccountSelectionRequested);
    }

    /**
     * OIDC Core §3.1.2.1 max_age: the last authentication must be no older than max_age seconds,
     * "auth_time + max_age < now" being too old (architecture §4.3). The session was authenticated two
     * hours ago.
     */
    #[Test]
    public function itRequiresAReauthenticationWhenTheLastOneIsOlderThanMaxAge(): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid()], Fixtures::now()));

        $this->loginRequired($this->handler->begin($this->request(maxAge: 7199), $this->session(), $this->context), LoginRequirement::MaxAgeExceeded);
        $this->granted($this->handler->begin($this->request(maxAge: 7200), $this->session(), $this->context));
        $this->granted($this->handler->begin($this->request(maxAge: 86400), $this->session(), $this->context));
    }

    /**
     * A login during the interaction satisfies max_age, whatever the seconds between the login and the
     * resume: otherwise max_age=0 could never be met.
     */
    #[Test]
    public function aLoginDuringTheInteractionSatisfiesMaxAge(): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid()], Fixtures::now()));
        $login = $this->loginRequired($this->handler->begin($this->request(maxAge: 0), null, $this->context), LoginRequirement::NoSession);

        $this->clock->sleep(5);
        $session = $this->session($this->clock->now());
        $this->clock->sleep(60);

        $this->granted($this->handler->resume($login->interaction, $session, $this->context));
    }

    /**
     * OIDC Core §3.1.2.1 id_token_hint: the session must be the user the hint names; the same user goes
     * through, another user has to log in.
     */
    #[Test]
    public function itComparesTheSessionToTheIdTokenHint(): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid()], Fixtures::now()));

        $this->granted($this->handler->begin($this->request(idTokenHint: self::ALICE_HINT), $this->session(), $this->context));
        $this->loginRequired($this->handler->begin($this->request(idTokenHint: self::BOB_HINT), $this->session(), $this->context), LoginRequirement::DifferentUser);
        $this->loginRequired($this->handler->begin($this->request(idTokenHint: self::BOB_HINT), null, $this->context), LoginRequirement::NoSession);
    }

    /**
     * A hint that was not issued here is refused before anything else, with or without a session: the
     * error goes back to the client and the interaction is over.
     */
    #[Test]
    public function itRefusesAForgedIdTokenHintBeforeAskingForALogin(): void
    {
        foreach ([null, $this->session()] as $session) {
            try {
                $this->handler->begin($this->request(idTokenHint: self::FORGED_HINT), $session, $this->context);
                static::fail('The request should have been refused.');
            } catch (InvalidRequestException $exception) {
                static::assertTrue($exception->redirectable);
                static::assertStringContainsString('id_token_hint', $exception->errorDescription);
            }
            static::assertTrue($this->savedInteraction()->isCompleted());
        }
    }

    /**
     * Architecture §4.3, the whole path: login, consent, code. The consent is recorded for the scopes
     * of the request and announced with the request context.
     */
    #[Test]
    public function itResumesAfterTheLoginAndAfterTheConsent(): void
    {
        $request = $this->request(['openid', 'profile']);
        $login = $this->loginRequired($this->handler->begin($request, null, $this->context), LoginRequirement::NoSession);

        $this->clock->sleep(20);
        $session = $this->session($this->clock->now());
        $resumed = $this->interactions->find($login->interaction->id) ?? static::fail('The interaction should have been saved.');
        $consent = $this->consentRequired($this->handler->resume($resumed, $session, $this->context), ConsentRequirement::NotGranted);
        static::assertSame($login->interaction, $consent->interaction);

        $this->clock->sleep(20);
        $context = Fixtures::context($this->clock->now());
        $granted = $this->granted($this->handler->grantConsent($consent->interaction, $session, $context));

        $recorded = $granted->interaction->consent ?? static::fail('The consent should have been recorded.');
        static::assertSame([$recorded], $this->consents->all());
        static::assertSame($recorded, $this->consents->findActive($this->alice, $this->client));
        static::assertSame($this->alice, $recorded->user);
        static::assertSame($this->client, $recorded->client);
        static::assertSame($request->scopes, $recorded->scopes);
        static::assertEquals($this->clock->now(), $recorded->grantedAt);

        $events = $this->events->of(ConsentGranted::class);
        static::assertCount(1, $events);
        static::assertSame($recorded, $events[0]->consent);
        static::assertNull($events[0]->supersedes);
        static::assertSame($context, $events[0]->context);
        static::assertSame($this->tenant, $events[0]->tenant);
        static::assertEquals($this->clock->now(), $events[0]->occurredAt);
        static::assertCount(1, $this->events->of(AuthorizationCodeIssued::class));
        static::assertSame($context, $this->events->of(AuthorizationCodeIssued::class)[0]->context);
    }

    /**
     * The integration may show the consent page right after the login without a resume in between:
     * grantConsent() records the session it is given.
     */
    #[Test]
    public function itRecordsTheSessionItIsGivenTheConsentWith(): void
    {
        $login = $this->loginRequired($this->handler->begin($this->request(), null, $this->context), LoginRequirement::NoSession);
        $session = $this->session($this->clock->now());

        $granted = $this->granted($this->handler->grantConsent($login->interaction, $session, $this->context));

        static::assertSame($session, $granted->interaction->session);
        static::assertSame($session, $granted->code->session);
    }

    /**
     * A new grant adds the scopes of the request to what the user had already granted the client, and
     * supersedes the previous consent, which is revoked.
     */
    #[Test]
    public function aNewConsentSupersedesThePreviousOne(): void
    {
        $previous = new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid(), new Scope('email')], Fixtures::now());
        $this->consents->save($previous);
        $consent = $this->consentRequired($this->handler->begin($this->request(['openid', 'profile']), $this->session(), $this->context), ConsentRequirement::NotGranted);

        $granted = $this->granted($this->handler->grantConsent($consent->interaction, $consent->session, $this->context));

        $recorded = $granted->interaction->consent ?? static::fail('The consent should have been recorded.');
        static::assertEquals([Scope::openid(), new Scope('email'), new Scope('profile')], $recorded->scopes);
        static::assertFalse($previous->isActive());
        static::assertEquals($this->clock->now(), $previous->revokedAt);
        static::assertSame($recorded, $this->consents->findActive($this->alice, $this->client));
        static::assertCount(2, $this->consents->all());
        static::assertSame(3, $this->consents->saves, 'the previous consent is saved revoked, then the new one');
        static::assertSame($previous, $this->events->of(ConsentGranted::class)[0]->supersedes);
    }

    /**
     * OIDC Core §3.1.2.1 prompt=consent: the question is put again even with a consent in force; the
     * consent given during the interaction satisfies it.
     */
    #[Test]
    public function itAsksAgainWhenPromptIsConsent(): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid(), new Scope('profile')], Fixtures::now()));
        $session = $this->session();

        $consent = $this->consentRequired($this->handler->begin($this->request(prompts: [Prompt::Consent]), $session, $this->context), ConsentRequirement::ConsentRequested);
        $this->consentRequired($this->handler->resume($consent->interaction, $session, $this->context), ConsentRequirement::ConsentRequested);
        $this->granted($this->handler->grantConsent($consent->interaction, $session, $this->context));
    }

    /**
     * The session ended between the consent page and its answer: nothing is recorded, the user logs in.
     */
    #[Test]
    public function itRecordsNoConsentWithoutAnActiveSession(): void
    {
        $session = $this->session();
        $consent = $this->consentRequired($this->handler->begin($this->request(), $session, $this->context), ConsentRequirement::NotGranted);
        $session->end(SessionEnd::User, $this->clock->now());

        $this->loginRequired($this->handler->grantConsent($consent->interaction, $session, $this->context), LoginRequirement::NoSession);
        static::assertSame([], $this->consents->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * RFC 6749 §4.1.2.1: the user refused, access_denied goes back to the client and the interaction is
     * over.
     */
    #[Test]
    public function itDeniesWhenTheUserRefuses(): void
    {
        $consent = $this->consentRequired($this->handler->begin($this->request(), $this->session(), $this->context), ConsentRequirement::NotGranted);

        try {
            $this->handler->deny($consent->interaction);
        } catch (AccessDeniedException $exception) {
            static::assertSame('access_denied', $exception->error);
            static::assertTrue($exception->redirectable);
            static::assertSame('The end user denied the request.', $exception->errorDescription);
        }
        static::assertTrue($consent->interaction->isCompleted());
        static::assertSame(2, $this->interactions->saves, 'saved when parked, saved again completed');
        static::assertSame([], $this->consents->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * Acceptance of #6: an interaction is not resumed twice, whatever ended it.
     */
    #[Test]
    public function itDoesNotResumeACompletedInteraction(): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $this->client, [Scope::openid()], Fixtures::now()));
        $session = $this->session();
        $granted = $this->granted($this->handler->begin($this->request(), $session, $this->context));
        $ended = $this->session();
        $ended->end(SessionEnd::User, $this->clock->now());

        foreach ([
            fn () => $this->handler->resume($granted->interaction, $session, $this->context),
            fn () => $this->handler->resume($granted->interaction, null, $this->context),
            fn () => $this->handler->grantConsent($granted->interaction, $session, $this->context),
            fn () => $this->handler->grantConsent($granted->interaction, $ended, $this->context),
            fn () => $this->handler->deny($granted->interaction),
        ] as $resume) {
            try {
                $resume();
                static::fail('The interaction should have been refused.');
            } catch (InteractionCompletedException $exception) {
                static::assertSame($granted->interaction->id, $exception->interactionId);
            }
        }
        static::assertCount(1, $this->codes->all());
    }

    /**
     * Acceptance of #6: an interaction is not resumed after its ten minutes.
     */
    #[Test]
    public function itDoesNotResumeAnExpiredInteraction(): void
    {
        $login = $this->loginRequired($this->handler->begin($this->request(), null, $this->context), LoginRequirement::NoSession);
        $this->clock->sleep(600);
        $session = $this->session($this->clock->now());
        $ended = $this->session($this->clock->now());
        $ended->end(SessionEnd::User, $this->clock->now());

        foreach ([
            fn () => $this->handler->resume($login->interaction, $session, $this->context),
            fn () => $this->handler->resume($login->interaction, null, $this->context),
            fn () => $this->handler->grantConsent($login->interaction, $session, $this->context),
            fn () => $this->handler->grantConsent($login->interaction, $ended, $this->context),
            fn () => $this->handler->deny($login->interaction),
        ] as $resume) {
            try {
                $resume();
                static::fail('The interaction should have been refused.');
            } catch (InteractionExpiredException $exception) {
                static::assertSame($login->interaction->id, $exception->interactionId);
            }
        }
        static::assertFalse($login->interaction->isCompleted());
    }

    /**
     * The lifetimes are the integration's to set; the defaults are those of architecture §4.3 and §4.4.
     */
    #[Test]
    public function theLifetimesAreConfigurable(): void
    {
        $handler = new AuthorizationHandler($this->interactions, $this->consents, $this->codes, new IdTokenHintVerifier(new FakeJwsVerifier()), $this->clock, $this->events, new DateInterval('PT5M'), new DateInterval('PT30S'));

        $granted = $this->granted($handler->begin(Requests::authorization($this->firstParty), $this->session(), $this->context));

        static::assertEquals($this->clock->now()->modify('+5 minutes'), $granted->interaction->expiresAt);
        static::assertEquals($this->clock->now()->modify('+30 seconds'), $granted->code->expiresAt);
    }

    /**
     * @param list<string> $scopes
     * @param list<Prompt> $prompts
     */
    private function request(array $scopes = ['openid'], array $prompts = [], ?int $maxAge = null, ?string $idTokenHint = null): AuthorizationRequest
    {
        return Requests::authorization($this->client, $scopes, $prompts, $maxAge, $idTokenHint);
    }

    /**
     * Alice, authenticated with a password at 10:00 by default, two hours before the clock of the tests.
     */
    private function session(?DateTimeImmutable $authenticatedAt = null): AuthenticationSession
    {
        return Fixtures::session($this->alice, $authenticatedAt);
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
