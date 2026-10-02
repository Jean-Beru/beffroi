<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Interaction;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InteractionTest extends TestCase
{
    private User $user;

    private Client $client;

    protected function setUp(): void
    {
        $this->user = Fixtures::user();
        $this->client = Clients::confidential($this->user->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
    }

    #[Test]
    public function itParksTheRequestWithTheLocale(): void
    {
        // Given
        $request = Requests::authorization($this->client);

        // When
        $interaction = new Interaction(Secrets::draw(), $this->user->tenant, $request, 'fr', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // Then
        static::assertSame($request, $interaction->request);
        static::assertSame($this->client->registration->clientId, $interaction->clientId);
        static::assertSame('fr', $interaction->locale);
    }

    #[Test]
    public function aNewInteractionHasNoSessionNoConsentAndIsNotCompleted(): void
    {
        // When
        $interaction = $this->interaction();

        // Then
        static::assertNull($interaction->session);
        static::assertNull($interaction->consent);
        static::assertNull($interaction->completedAt);
        static::assertFalse($interaction->isCompleted());
    }

    #[Test]
    public function itExpiresAtTheEndOfItsLifetime(): void
    {
        // Given
        $interaction = $this->interaction();

        // When / Then
        static::assertFalse($interaction->isExpired(Fixtures::now()->modify('+9 minutes 59 seconds')));
        static::assertTrue($interaction->isExpired(Fixtures::now()->modify('+10 minutes')));
    }

    #[Test]
    public function itRecordsTheSession(): void
    {
        // Given
        $interaction = $this->interaction();
        $session = Fixtures::session($this->user);

        // When
        $interaction->authenticate($session, Fixtures::now()->modify('+1 minute'));

        // Then
        static::assertSame($session, $interaction->session);
    }

    #[Test]
    public function itRecordsTheConsentAfterTheSession(): void
    {
        // Given
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now()->modify('+1 minute'));
        $consent = $this->consent();

        // When
        $interaction->consent($consent, Fixtures::now()->modify('+2 minutes'));

        // Then
        static::assertSame($consent, $interaction->consent);
    }

    #[Test]
    public function completingDatesTheCompletion(): void
    {
        // Given
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now()->modify('+1 minute'));
        $interaction->consent($this->consent(), Fixtures::now()->modify('+2 minutes'));

        // When
        $interaction->complete(Fixtures::now()->modify('+3 minutes'));

        // Then
        static::assertTrue($interaction->isCompleted());
        static::assertEquals(Fixtures::now()->modify('+3 minutes'), $interaction->completedAt);
    }

    #[Test]
    public function anotherSessionOfTheSameUserKeepsTheRecordedConsent(): void
    {
        // Given
        $interaction = $this->interaction();
        $consent = $this->consent();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());
        $interaction->consent($consent, Fixtures::now());

        // When
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());

        // Then
        static::assertSame($consent, $interaction->consent);
    }

    /**
     * A consent recorded for one user does not carry over to a session of another.
     */
    #[Test]
    public function aSessionOfAnotherUserDropsTheRecordedConsent(): void
    {
        // Given
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());
        $interaction->consent($this->consent(), Fixtures::now());

        // When
        $interaction->authenticate(Fixtures::session(Fixtures::user($this->user->tenant, 'bob', 'bob-subject')), Fixtures::now());

        // Then
        static::assertNull($interaction->consent);
    }

    /**
     * Acceptance of #6: an interaction cannot be resumed after expiry.
     *
     * @param callable(self, Interaction): void $resume
     */
    #[Test]
    #[DataProvider('provideResumptionsAfterExpiry')]
    public function itCannotBeResumedAfterExpiry(callable $resume): void
    {
        // Given
        $interaction = $this->interaction();

        // When
        try {
            $resume($this, $interaction);
            static::fail('The interaction should have been refused.');
        } catch (InteractionExpiredException $exception) {
            // Then
            static::assertSame($interaction->id, $exception->interactionId);
            static::assertStringContainsString('expired', $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{callable(self, Interaction): void}>
     */
    public static function provideResumptionsAfterExpiry(): iterable
    {
        $late = Fixtures::now()->modify('+10 minutes');
        yield 'authenticate' => [
            static fn (self $test, Interaction $interaction) => $interaction->authenticate(Fixtures::session($test->user), $late),
        ];
        yield 'complete' => [
            static fn (self $test, Interaction $interaction) => $interaction->complete($late),
        ];
        yield 'assert resumable' => [
            static fn (self $test, Interaction $interaction) => $interaction->assertResumable($late),
        ];
    }

    #[Test]
    public function aRefusedCompletionAfterExpiryLeavesItUncompleted(): void
    {
        // Given
        $interaction = $this->interaction();

        // When
        try {
            $interaction->complete(Fixtures::now()->modify('+10 minutes'));
        } catch (InteractionExpiredException) {
        }

        // Then
        static::assertFalse($interaction->isCompleted());
    }

    /**
     * Acceptance of #6: an interaction cannot be resumed twice.
     *
     * @param callable(self, Interaction): void $resume
     */
    #[Test]
    #[DataProvider('provideResumptionsAfterCompletion')]
    public function itCannotBeResumedOnceCompleted(callable $resume): void
    {
        // Given
        $interaction = $this->completedInteraction();

        // When
        try {
            $resume($this, $interaction);
            static::fail('The interaction should have been refused.');
        } catch (InteractionCompletedException $exception) {
            // Then
            static::assertSame($interaction->id, $exception->interactionId);
            static::assertStringContainsString('completed', $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{callable(self, Interaction): void}>
     */
    public static function provideResumptionsAfterCompletion(): iterable
    {
        yield 'authenticate' => [
            static fn (self $test, Interaction $interaction) => $interaction->authenticate(Fixtures::session($test->user), Fixtures::now()),
        ];
        yield 'consent' => [
            static fn (self $test, Interaction $interaction) => $interaction->consent($test->consent(), Fixtures::now()),
        ];
        yield 'complete' => [
            static fn (self $test, Interaction $interaction) => $interaction->complete(Fixtures::now()),
        ];
        yield 'assert resumable' => [
            static fn (self $test, Interaction $interaction) => $interaction->assertResumable(Fixtures::now()),
        ];
    }

    #[Test]
    public function aRefusedSecondCompletionKeepsTheFirstDate(): void
    {
        // Given
        $interaction = $this->completedInteraction();

        // When
        try {
            $interaction->complete(Fixtures::now()->modify('+2 minutes'));
        } catch (InteractionCompletedException) {
        }

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 minute'), $interaction->completedAt);
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        // Given
        $interaction = $this->interaction();
        $session = Fixtures::session(Fixtures::user(Fixtures::tenant('other', 'https://id.other.example')));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $interaction->authenticate($session, Fixtures::now());
    }

    #[Test]
    public function itRefusesASessionThatIsNotActive(): void
    {
        // Given
        $interaction = $this->interaction();
        $session = Fixtures::session($this->user);
        $session->end(SessionEnd::User, Fixtures::now());

        // Then
        $this->expectException(LogicException::class);

        // When
        $interaction->authenticate($session, Fixtures::now());
    }

    #[Test]
    public function itRefusesAConsentBeforeASession(): void
    {
        // Given
        $interaction = $this->interaction();

        // Then
        $this->expectException(LogicException::class);

        // When
        $interaction->consent($this->consent(), Fixtures::now());
    }

    /**
     * @param callable(self): Consent $consent
     */
    #[Test]
    #[DataProvider('provideConsentsOfSomeoneElse')]
    public function itRefusesAConsentOfAnotherUserOrClient(callable $consent): void
    {
        // Given
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('user of the session and the client of the request');

        // When
        $interaction->consent($consent($this), Fixtures::now());
    }

    /**
     * @return iterable<string, array{callable(self): Consent}>
     */
    public static function provideConsentsOfSomeoneElse(): iterable
    {
        yield 'another user' => [
            static fn (self $test): Consent => new Consent(
                Uuid::v7(),
                Fixtures::user($test->user->tenant, 'bob', 'bob-subject'),
                $test->client,
                new Scopes([new Scope('openid'), new Scope('profile')]),
                Fixtures::now(),
            ),
        ];
        yield 'another client' => [
            static fn (self $test): Consent => new Consent(
                Uuid::v7(),
                $test->user,
                Clients::public($test->user->tenant),
                new Scopes([new Scope('openid'), new Scope('profile')]),
                Fixtures::now(),
            ),
        ];
    }

    #[Test]
    public function itRefusesAConsentThatDoesNotCoverTheRequest(): void
    {
        // Given
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $interaction->consent(new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([new Scope('openid')]), Fixtures::now()), Fixtures::now());
    }

    /**
     * RFC 9396 §7: a consent recorded on an interaction covers the authorization details of the request as
     * it covers its scopes, or the answer would be a code for something nobody agreed to.
     */
    #[Test]
    public function itRefusesAConsentThatDoesNotCoverTheDetailsOfTheRequest(): void
    {
        // Given
        $interaction = new Interaction(
            Secrets::draw(),
            $this->user->tenant,
            Requests::authorization($this->client, ['openid', 'profile'], authorizationDetails: AuthorizationDetailTypes::details()),
            null,
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A consent recorded on an interaction covers every authorization detail of the request (RFC 9396 section 7).');

        // When
        $interaction->consent($this->consent(), Fixtures::now());
    }

    #[Test]
    #[DataProvider('provideMalformedIdentifiers')]
    public function itRefusesAMalformedIdentifier(string $id): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('256 bits');

        // When
        new Interaction($id, $this->user->tenant, Requests::authorization($this->client), null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedIdentifiers(): iterable
    {
        yield 'empty' => [''];
        yield 'short' => ['short'];
        yield 'padded' => [Secrets::draw() . '='];
        yield 'too long' => [Secrets::draw() . 'a'];
        yield 'standard base64 alphabet' => ['E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM'];
    }

    #[Test]
    public function itRefusesAClientOfAnotherTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Interaction(
            Secrets::draw(),
            Fixtures::tenant('other', 'https://id.other.example'),
            Requests::authorization($this->client),
            null,
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
    }

    #[Test]
    public function itRefusesAnEmptyLocale(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Interaction(
            Secrets::draw(),
            $this->user->tenant,
            Requests::authorization($this->client),
            '',
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasCreated(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Interaction(Secrets::draw(), $this->user->tenant, Requests::authorization($this->client), null, Fixtures::now(), Fixtures::now());
    }

    private function interaction(?DateTimeImmutable $createdAt = null): Interaction
    {
        $createdAt ??= Fixtures::now();

        return new Interaction(
            Secrets::draw(),
            $this->user->tenant,
            Requests::authorization($this->client, ['openid', 'profile']),
            null,
            $createdAt,
            $createdAt->modify('+10 minutes'),
        );
    }

    private function completedInteraction(): Interaction
    {
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());
        $interaction->complete(Fixtures::now()->modify('+1 minute'));

        return $interaction;
    }

    private function consent(): Consent
    {
        return new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([new Scope('openid'), new Scope('profile')]), Fixtures::now());
    }
}
