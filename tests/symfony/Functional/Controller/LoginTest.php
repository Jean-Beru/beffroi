<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use DateTimeImmutable;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Event\AuthenticationFailed;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Event\AuthenticationSessionEnded;
use Heidi\Core\Domain\Event\PasswordRehashed;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §5.4, the acceptance criterion of the security of the bundle: a user created outside of
 * the browser signs in on the form of the login page, the firewall opens the session of the core and
 * binds the browser to it, and an interaction begun in another HTTP session cannot be resumed, before
 * or after a login. The firewall is the one of tests/symfony/config/config_test.yml, declared as an
 * application declares it.
 */
final class LoginTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Architecture §5.4: the login of the firewall sends the browser back to the login page of the
     * interaction, which resumes it.
     */
    #[Test]
    public function aSuccessfulLoginGoesBackToTheLoginPageOfTheInteraction(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        self::assertInteractionHeaders($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * OIDC Core §2 (auth_time, amr), RFC 8176 §2, architecture §3.2 and §3.5: the session of the core
     * says who, since when, how, from where.
     */
    #[Test]
    public function aSuccessfulLoginOpensASessionOfTheCore(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $before = new DateTimeImmutable();
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $session = $this->boundSession();
        static::assertTrue($session->user->id->equals($user->id));
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertGreaterThanOrEqual(
            $before->setTime((int) $before->format('H'), (int) $before->format('i'), (int) $before->format('s')),
            $session->authenticatedAt(),
        );
        static::assertLessThanOrEqual(new DateTimeImmutable('+5 seconds'), $session->authenticatedAt());
        static::assertSame('127.0.0.1', $session->createdFrom->ipAddress);
        static::assertSame('Symfony BrowserKit', $session->createdFrom->userAgent);
        static::assertTrue($session->isActive(new DateTimeImmutable()));
        static::assertSame('1', $session->authenticationContextClass()->value);
    }

    /**
     * The token of the firewall calls recent what the session calls auth_time (symfony/symfony#66014).
     */
    #[Test]
    public function theTokenOfTheFirewallCarriesTheAuthTimeOfTheSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame(
            [
                'pwd' => $this->boundSession()->authenticatedAt()->getTimestamp(),
            ],
            $this->securityToken()->getAuthenticationProofs(),
        );
    }

    #[Test]
    public function aSuccessfulLoginDatesTheUseOfTheCredential(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $credential = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)
            ->findByUser($this->boundSession()->user, PasswordCredential::class)[0] ?? static::fail('The credential is gone.');
        static::assertNotNull($credential->lastUsedAt);
    }

    /**
     * Architecture §3.5: the core is told once; a hash the policy produces is not rehashed.
     */
    #[Test]
    public function aSuccessfulLoginIsAnnouncedOnce(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $events = self::events(UserAuthenticated::class);
        static::assertCount(1, $events);
        static::assertTrue($events[0]->session->id->equals($this->boundSession()->id));
        static::assertSame([], self::events(PasswordRehashed::class));
    }

    /**
     * The interaction the browser began goes on with the session: consent is next.
     */
    #[Test]
    public function theInteractionGoesOnWithTheSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §4.3: an interaction is resumed by the browser that began it and by no other.
     */
    #[Test]
    public function anotherBrowserCannotSeeTheLoginPageOfAnInteraction(): void
    {
        // Given
        $interaction = $this->authorize();
        $this->browser->getCookieJar()->clear();

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Nor is its form for another browser, whatever it posts: the firewall refuses a form token it did
     * not give this browser.
     */
    #[Test]
    public function anotherBrowserCannotPostTheLoginFormOfAnInteraction(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $token = $this->csrfTokenOfTheLoginPage($interaction);
        $this->browser->getCookieJar()->clear();

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, $token);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    #[Test]
    public function aLoginPostedByAnotherBrowserOpensNoSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $token = $this->csrfTokenOfTheLoginPage($interaction);
        $this->browser->getCookieJar()->clear();

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, $token);

        // Then
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    /**
     * Signed in on an interaction of its own, a browser still cannot touch one begun elsewhere.
     */
    #[Test]
    #[DataProvider('providePagesOfAnInteraction')]
    public function aBrowserSignedInOnItsOwnInteractionCannotResumeAnotherOne(string $path): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->browser->getCookieJar()->clear();
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', $path, [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePagesOfAnInteraction(): iterable
    {
        yield 'the login page' => ['/login'];
        yield 'the consent page' => ['/consent'];
    }

    #[Test]
    public function anInteractionAnotherBrowserTriedToResumeIsStillPending(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->browser->getCookieJar()->clear();
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertFalse(self::service('test.heidi.interactions', InteractionRepositoryInterface::class)->find($interaction)?->isCompleted());
    }

    /**
     * Decision 0006 and architecture §3.4: a wrong password sends the browser back to the form.
     */
    #[Test]
    public function aWrongPasswordGoesBackToTheLoginPage(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    #[Test]
    public function aWrongPasswordOpensNoSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.4: the audit trail gets the reason and the request context.
     */
    #[Test]
    public function aWrongPasswordIsRecordedWithItsReason(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertSame('alice', $failures[0]->identifier);
        static::assertTrue($failures[0]->user?->id->equals($user->id));
        static::assertSame('127.0.0.1', $failures[0]->context->ipAddress);
    }

    /**
     * Decision 0006: the user gets one message whatever the reason, the username kept.
     */
    #[Test]
    public function afterAWrongPasswordTheFormShowsOneMessageAndKeepsTheUsername(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', 'not the password');

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('authentication_failed', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame('alice', $crawler->filter('input[name="_username"]')->attr('value'));
    }

    #[Test]
    public function theMessageOfAFailedLoginIsShownOnce(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', 'not the password');
        $this->loginPage($interaction);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertCount(0, $crawler->filter('p[data-error]'));
    }

    /**
     * Decision 0006: an unknown user, a disabled user and a user without a password are refused exactly
     * like a wrong password.
     *
     * @param callable(): ?User $user
     */
    #[Test]
    #[DataProvider('provideUsersRefusedLikeAWrongPassword')]
    public function anUnknownADisabledOrAPasswordlessUserIsRefusedLikeAWrongPassword(
        string $username,
        callable $user,
        AuthenticationFailureReason $reason,
    ): void {
        // Given
        $user();
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, $username, self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf($username));
        static::assertSame('authentication_failed', $this->loginPage($interaction)->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * Decision 0006: only the audit trail tells them apart.
     *
     * @param callable(): ?User $user
     */
    #[Test]
    #[DataProvider('provideUsersRefusedLikeAWrongPassword')]
    public function theAuditTrailTellsTheReasonOfARefusedLogin(string $username, callable $user, AuthenticationFailureReason $reason): void
    {
        // Given
        $refused = $user();
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, $username, self::PASSWORD);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame($reason, $failures[0]->reason);
        static::assertSame($username, $failures[0]->identifier);
        if ($refused === null) {
            static::assertNull($failures[0]->user);
        } else {
            static::assertTrue($failures[0]->user?->id->equals($refused->id));
        }
    }

    /**
     * @return iterable<string, array{string, callable(): ?User, AuthenticationFailureReason}>
     */
    public static function provideUsersRefusedLikeAWrongPassword(): iterable
    {
        yield 'unknown' => [
            'nobody',
            static fn (): ?User => null,
            AuthenticationFailureReason::UnknownUser,
        ];
        yield 'disabled' => [
            'bob',
            static function (): User {
                $disabled = self::userWithPassword('bob', self::PASSWORD);
                $disabled->disable(self::now());
                self::service('test.heidi.users', UserRepositoryInterface::class)->save($disabled);

                return $disabled;
            },
            AuthenticationFailureReason::DisabledUser,
        ];
        yield 'without a password' => [
            'carol',
            static fn (): User => self::user('carol', 'carol-subject'),
            AuthenticationFailureReason::NoSuchCredential,
        ];
    }

    /**
     * Decision 0006 and architecture §3.4: five attempts a minute on a user, counted before the hash is
     * verified; the sixth is refused whatever the password, the right one included.
     */
    #[Test]
    public function theSixthAttemptInAMinuteOpensNoSessionWhateverThePassword(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.4: the audit trail says the attempt was refused before the password was looked at.
     */
    #[Test]
    public function aRefusedAttemptIsRecordedWithItsReason(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, $failures[0]->reason);
        static::assertSame('alice', $failures[0]->identifier);
        static::assertTrue($failures[0]->user?->id->equals($user->id));
    }

    /**
     * Decision 0006: the user is told "failed" and nothing more, as after any other refusal.
     */
    #[Test]
    public function aRefusedAttemptIsShownLikeAnyOtherFailure(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('authentication_failed', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * The count is per user and never per address: what was tried on alice does not count for bob.
     */
    #[Test]
    public function theAttemptsOnOneUserDoNotCountForAnother(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $bob = self::userWithPassword('bob', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }

        // When
        $this->submitLogin($interaction, 'bob', self::PASSWORD);

        // Then
        static::assertTrue($this->boundSession()->user->id->equals($bob->id));
    }

    /**
     * Architecture §3.4: a password the firewall accepted empties the count of the user, so that four
     * mistakes before a login do not count against the next one.
     */
    #[Test]
    public function aSuccessfulLoginEmptiesTheCountOfTheUser(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            $this->submitLogin($interaction, 'alice', 'not the password');
        }

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertCount(1, self::sessionsOf('alice'));
    }

    /**
     * A form posted without the token of this browser is refused.
     */
    #[Test]
    public function aFormWithoutItsTokenIsRefused(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->loginPage($interaction);

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, 'not-the-token');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertSame('authentication_failed', $this->loginPage($interaction)->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * A form posted without its token is not an attempt on an account: nothing opened, nothing recorded.
     */
    #[Test]
    public function aFormWithoutItsTokenRecordsNothing(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->loginPage($interaction);

        // When
        $this->postLogin($interaction, 'alice', self::PASSWORD, 'not-the-token');

        // Then
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.4: a hash weaker than the policy of the core is replaced on the login that verified
     * it; the password itself did not change.
     */
    #[Test]
    public function aHashWeakerThanThePolicyIsRehashedOnLogin(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD, PasswordAlgorithm::Bcrypt);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        $credential = $this->credentialOf($user);
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertNotNull($credential->lastUsedAt);
    }

    /**
     * Architecture §3.4: the core is told of the rehash, with the request context.
     */
    #[Test]
    public function aRehashOnLoginIsAnnounced(): void
    {
        // Given
        $user = self::userWithPassword('alice', self::PASSWORD, PasswordAlgorithm::Bcrypt);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $rehashes = self::events(PasswordRehashed::class);
        static::assertCount(1, $rehashes);
        static::assertTrue($rehashes[0]->credential->id->equals($this->credentialOf($user)->id));
        static::assertSame('127.0.0.1', $rehashes[0]->context->ipAddress);
    }

    /**
     * The new hash opens the session next time too, and is not rehashed again.
     */
    #[Test]
    public function theRehashedPasswordOpensTheSessionNextTime(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD, PasswordAlgorithm::Bcrypt);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $this->browser->getCookieJar()->clear();

        // When
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // Then
        static::assertCount(2, self::sessionsOf('alice'));
        static::assertSame([], self::events(PasswordRehashed::class));
    }

    /**
     * OIDC Core §3.1.2.1 (prompt=login): the login page tells the signed-in user a fresh login is asked.
     */
    #[Test]
    public function theLoginPageSaysWhenAFreshLoginIsAsked(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('reauthentication_requested', $crawler->filter('p[data-requirement]')->attr('data-requirement'));
    }

    /**
     * OIDC Core §3.1.2.1 (prompt=login) and architecture §3.2: a fresh login asked by a client records a
     * proof on the session the browser has, it does not open a second one.
     */
    #[Test]
    public function aFreshLoginAskedByTheClientRecordsAProofOnTheExistingSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $first = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        $session = $this->boundSession();
        static::assertTrue($session->id->equals($first->id));
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertGreaterThanOrEqual($first->authenticatedAt(), $session->authenticatedAt());
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');
    }

    #[Test]
    public function aFreshLoginMovesTheAuthTimeOfTheToken(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame(
            [
                'pwd' => $this->boundSession()->authenticatedAt()->getTimestamp(),
            ],
            $this->securityToken()->getAuthenticationProofs(),
        );
    }

    /**
     * The interaction goes on: the login is fresh.
     */
    #[Test]
    public function theInteractionGoesOnAfterAFreshLogin(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §3.2: two users do not share a cookie. Someone else signing in on a bound browser
     * opens their own session.
     */
    #[Test]
    public function anotherUserSigningInOnABoundBrowserOpensTheirOwnSession(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        self::userWithPassword('bob', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $alice = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $this->submitLogin($interaction, 'bob', self::PASSWORD);

        // Then
        $bob = $this->boundSession();
        static::assertTrue($bob->user->id->equals(self::sessionsOf('bob')[0]->user->id));
        static::assertFalse($bob->id->equals($alice->id));
        static::assertCount(1, self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.2: someone else signing in on a bound browser ends the session of the first user.
     */
    #[Test]
    public function anotherUserSigningInOnABoundBrowserEndsTheSessionOfTheFirst(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        self::userWithPassword('bob', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);
        $alice = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $this->submitLogin($interaction, 'bob', self::PASSWORD);

        // Then
        $ended = self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($alice->id) ?? static::fail('The session of alice is gone.');
        static::assertTrue($ended->hasEnded());
        static::assertSame(SessionEnd::User, $ended->endedBy);
        $endings = self::events(AuthenticationSessionEnded::class);
        static::assertCount(1, $endings);
        static::assertTrue($endings[0]->session->id->equals($alice->id));
    }

    /**
     * Architecture §5.2: the protocol plane sits outside of the firewall, no cookie is read there and no
     * session started, whatever the request.
     */
    #[Test]
    #[DataProvider('provideProtocolRequests')]
    public function theProtocolPlaneStartsNoSession(string $method, string $path): void
    {
        // When
        $this->browser->request($method, $path);

        // Then
        static::assertFalse($this->browser->getResponse()->headers->has('Set-Cookie'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideProtocolRequests(): iterable
    {
        yield 'discovery' => ['GET', '/.well-known/openid-configuration'];
        yield 'authorization server metadata' => ['GET', '/.well-known/oauth-authorization-server'];
        yield 'jwks' => ['GET', '/jwks'];
        yield 'token' => ['POST', '/token'];
        yield 'userinfo' => ['GET', '/userinfo'];
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return string the identifier of the interaction the browser was sent to the login page with
     */
    private function authorize(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters(parameters: $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));

        return $interaction;
    }

    private function loginPage(string $interaction): Crawler
    {
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    private function csrfTokenOfTheLoginPage(string $interaction): string
    {
        $token = $this->loginPage($interaction)->filter('input[name="_csrf_token"]')->attr('value');
        static::assertIsString($token);

        return $token;
    }

    /**
     * Fills and posts the form of the login page, as a user does.
     */
    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    /**
     * Posts the login form without reading the page, with the token given.
     */
    private function postLogin(string $interaction, string $username, string $password, string $token): void
    {
        $this->browser->request('POST', '/login?interaction=' . $interaction, [
            '_username' => $username,
            '_password' => $password,
            '_csrf_token' => $token,
        ]);
    }

    private function credentialOf(User $user): PasswordCredential
    {
        $managed = self::service('test.heidi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');

        return (
            self::service('test.heidi.credentials', CredentialRepositoryInterface::class)
                ->findByUser($managed, PasswordCredential::class)[0] ?? static::fail('The credential is gone.')
        );
    }

    /**
     * The session of the core the browser is bound to, read from the rows.
     */
    private function boundSession(): AuthenticationSession
    {
        $id = $this->readHttpSession()->get(BrowserSession::AUTHENTICATION_SESSION_KEY);
        static::assertIsString($id, 'The browser is bound to no session.');
        self::reload();

        return (
            self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString($id)) ?? static::fail('The bound session is gone.')
        );
    }

    /**
     * The token the firewall stored in the HTTP session of the browser.
     */
    private function securityToken(): TokenInterface
    {
        $serialized = $this->readHttpSession()->get('_security_heidi_interaction');
        static::assertIsString($serialized, 'The firewall stored no token.');
        $token = unserialize($serialized);
        static::assertInstanceOf(TokenInterface::class, $token);

        return $token;
    }

    /**
     * The active sessions of a user, from the rows.
     *
     * @return list<AuthenticationSession>
     */
    private static function sessionsOf(string $username): array
    {
        self::reload();
        $user = self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), $username);
        if (! $user instanceof User) {
            return [];
        }

        return self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->findActiveByUser($user, new DateTimeImmutable());
    }

    /**
     * The events of a class that reached the event bus during the last request.
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    private static function events(string $class): array
    {
        $events = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof $class) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
