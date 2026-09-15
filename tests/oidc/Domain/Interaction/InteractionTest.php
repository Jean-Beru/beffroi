<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Interaction;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
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

    /**
     * Architecture §4.3: the identifier is 256 random bits in base64url, never guessable.
     */
    #[Test]
    public function itsIdentifierIsRandom(): void
    {
        $id = Interaction::generateId();

        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $id));
        static::assertNotSame($id, Interaction::generateId());
    }

    #[Test]
    public function itParksTheRequest(): void
    {
        $request = Requests::authorization($this->client);

        $interaction = new Interaction(Interaction::generateId(), $this->user->tenant, $request, 'fr', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        static::assertSame($request, $interaction->request);
        static::assertSame('fr', $interaction->locale);
        static::assertNull($interaction->session);
        static::assertNull($interaction->consent);
        static::assertNull($interaction->completedAt);
        static::assertFalse($interaction->isCompleted());
        static::assertFalse($interaction->isExpired(Fixtures::now()->modify('+9 minutes 59 seconds')));
        static::assertTrue($interaction->isExpired(Fixtures::now()->modify('+10 minutes')));
    }

    #[Test]
    public function itRecordsTheSessionThenTheConsent(): void
    {
        $interaction = $this->interaction();
        $session = Fixtures::session($this->user);
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, [new Scope('openid'), new Scope('profile')], Fixtures::now());

        $interaction->authenticate($session, Fixtures::now()->modify('+1 minute'));
        $interaction->consent($consent, Fixtures::now()->modify('+2 minutes'));
        $interaction->complete(Fixtures::now()->modify('+3 minutes'));

        static::assertSame($session, $interaction->session);
        static::assertSame($consent, $interaction->consent);
        static::assertTrue($interaction->isCompleted());
        static::assertEquals(Fixtures::now()->modify('+3 minutes'), $interaction->completedAt);
    }

    /**
     * A consent recorded for one user does not carry over to a session of another.
     */
    #[Test]
    public function aSessionOfAnotherUserDropsTheRecordedConsent(): void
    {
        $interaction = $this->interaction();
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, [new Scope('openid'), new Scope('profile')], Fixtures::now());
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());
        $interaction->consent($consent, Fixtures::now());

        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());
        static::assertSame($consent, $interaction->consent);

        $interaction->authenticate(Fixtures::session(Fixtures::user($this->user->tenant, 'bob', 'bob-subject')), Fixtures::now());
        static::assertNull($interaction->consent);
    }

    /**
     * Acceptance of #6: an interaction cannot be resumed after expiry.
     */
    #[Test]
    public function itCannotBeResumedAfterExpiry(): void
    {
        $interaction = $this->interaction();
        $late = Fixtures::now()->modify('+10 minutes');

        foreach ([
            fn () => $interaction->authenticate(Fixtures::session($this->user), $late),
            fn () => $interaction->complete($late),
            fn () => $interaction->assertResumable($late),
        ] as $resume) {
            try {
                $resume();
                static::fail('The interaction should have been refused.');
            } catch (InteractionExpiredException $exception) {
                static::assertSame($interaction->id, $exception->interactionId);
                static::assertStringContainsString('expired', $exception->getMessage());
            }
        }
        static::assertFalse($interaction->isCompleted());
    }

    /**
     * Acceptance of #6: an interaction cannot be resumed twice.
     */
    #[Test]
    public function itCannotBeResumedOnceCompleted(): void
    {
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());
        $interaction->complete(Fixtures::now()->modify('+1 minute'));
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, [new Scope('openid'), new Scope('profile')], Fixtures::now());

        foreach ([
            fn () => $interaction->authenticate(Fixtures::session($this->user), Fixtures::now()),
            fn () => $interaction->consent($consent, Fixtures::now()),
            fn () => $interaction->complete(Fixtures::now()),
            fn () => $interaction->assertResumable(Fixtures::now()),
        ] as $resume) {
            try {
                $resume();
                static::fail('The interaction should have been refused.');
            } catch (InteractionCompletedException $exception) {
                static::assertSame($interaction->id, $exception->interactionId);
                static::assertStringContainsString('completed', $exception->getMessage());
            }
        }
        static::assertEquals(Fixtures::now()->modify('+1 minute'), $interaction->completedAt);
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        $interaction = $this->interaction();

        $this->expectException(InvalidArgumentException::class);
        $interaction->authenticate(Fixtures::session(Fixtures::user(Fixtures::tenant('other', 'https://id.other.example'))), Fixtures::now());
    }

    #[Test]
    public function itRefusesASessionThatIsNotActive(): void
    {
        $interaction = $this->interaction();
        $session = Fixtures::session($this->user);
        $session->end(SessionEnd::User, Fixtures::now());

        $this->expectException(LogicException::class);
        $interaction->authenticate($session, Fixtures::now());
    }

    #[Test]
    public function itRefusesAConsentBeforeASession(): void
    {
        $interaction = $this->interaction();

        $this->expectException(LogicException::class);
        $interaction->consent(new Consent(Uuid::v7(), $this->user, $this->client, [new Scope('openid'), new Scope('profile')], Fixtures::now()), Fixtures::now());
    }

    #[Test]
    public function itRefusesAConsentOfAnotherUserOrClient(): void
    {
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());
        $bob = Fixtures::user($this->user->tenant, 'bob', 'bob-subject');

        foreach ([
            new Consent(Uuid::v7(), $bob, $this->client, [new Scope('openid'), new Scope('profile')], Fixtures::now()),
            new Consent(Uuid::v7(), $this->user, Clients::public($this->user->tenant), [new Scope('openid'), new Scope('profile')], Fixtures::now()),
        ] as $consent) {
            try {
                $interaction->consent($consent, Fixtures::now());
                static::fail('The consent should have been refused.');
            } catch (InvalidArgumentException $exception) {
                static::assertStringContainsString('user of the session and the client of the request', $exception->getMessage());
            }
        }
    }

    #[Test]
    public function itRefusesAConsentThatDoesNotCoverTheRequest(): void
    {
        $interaction = $this->interaction();
        $interaction->authenticate(Fixtures::session($this->user), Fixtures::now());

        $this->expectException(InvalidArgumentException::class);
        $interaction->consent(new Consent(Uuid::v7(), $this->user, $this->client, [new Scope('openid')], Fixtures::now()), Fixtures::now());
    }

    #[Test]
    public function itRefusesAMalformedIdentifier(): void
    {
        foreach (['', 'short', Interaction::generateId() . '=', Interaction::generateId() . 'a', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM'] as $id) {
            try {
                new Interaction($id, $this->user->tenant, Requests::authorization($this->client), null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
                static::fail('The identifier should have been refused.');
            } catch (InvalidArgumentException $exception) {
                static::assertStringContainsString('256 bits', $exception->getMessage());
            }
        }
    }

    #[Test]
    public function itRefusesAClientOfAnotherTenant(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Interaction(Interaction::generateId(), Fixtures::tenant('other', 'https://id.other.example'), Requests::authorization($this->client), null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    #[Test]
    public function itRefusesAnEmptyLocale(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Interaction(Interaction::generateId(), $this->user->tenant, Requests::authorization($this->client), '', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasCreated(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Interaction(Interaction::generateId(), $this->user->tenant, Requests::authorization($this->client), null, Fixtures::now(), Fixtures::now());
    }

    private function interaction(?DateTimeImmutable $createdAt = null): Interaction
    {
        $createdAt ??= Fixtures::now();

        return new Interaction(Interaction::generateId(), $this->user->tenant, Requests::authorization($this->client, ['openid', 'profile']), null, $createdAt, $createdAt->modify('+10 minutes'));
    }
}
