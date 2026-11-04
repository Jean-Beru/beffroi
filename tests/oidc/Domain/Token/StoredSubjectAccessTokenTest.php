<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\StoredSubjectAccessToken;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8693 §2.1, RFC 7523 §2.1, Architecture §4.6
 */
final class StoredSubjectAccessTokenTest extends TestCase
{
    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function itNamesThePersonItIsInTheNameOf(): void
    {
        // Given
        $session = Fixtures::session();
        $record = Tokens::storedSubjectAccessToken(
            'the-value',
            Clients::gateway($session->tenant, new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('the-sub-of-the-first-client'),
            Fixtures::now(),
            session: $session,
        );

        // When / Then
        static::assertTrue($session->user->subject->equals($record->person() ?? static::fail('The record names nobody.')));
    }

    /**
     * RFC 9068 §2.2.1
     */
    #[Test]
    public function itNamesItsPersonItselfWhateverSessionItNames(): void
    {
        // Given
        $session = Fixtures::session();
        $record = Tokens::storedSubjectAccessToken(
            'the-value',
            Clients::gateway($session->tenant, new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('the-sub-of-the-first-client'),
            Fixtures::now(),
            session: $session,
        );

        // When / Then
        static::assertNull($record->sessionNamingItsPerson());
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function itNamesNobodyWhenNothingReadTheSubjectBackAsAPerson(): void
    {
        // Given
        $record = Tokens::storedSubjectAccessToken(
            'the-value',
            Clients::gateway(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('service-app'),
            Fixtures::now(),
        );

        // When / Then
        static::assertNull($record->person());
    }

    /**
     * RFC 9068 §2.2.1
     */
    #[Test]
    public function itReadsBackTheSignInThePresentedTokenNamed(): void
    {
        // Given
        $session = Fixtures::session();
        $record = Tokens::storedSubjectAccessToken(
            'the-value',
            Clients::gateway($session->tenant, new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('alice-subject'),
            Fixtures::now(),
            session: $session,
        );

        // When
        $signIn = $record->signIn();

        // Then
        static::assertTrue($signIn?->sessionId->equals($session->id));
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function aRecordThatNamesNoSessionNamesNoSignIn(): void
    {
        // Given
        $record = Tokens::storedSubjectAccessToken(
            'the-value',
            Clients::gateway(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('batch'),
            Fixtures::now(),
        );

        // When / Then
        static::assertNull($record->signIn());
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function itIsAddressedToTheResourcesItWasAskedFor(): void
    {
        // Given
        $record = Tokens::storedSubjectAccessToken(
            'the-value',
            Clients::gateway(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('alice-subject'),
            Fixtures::now(),
            resources: ResourceIndicators::of([Clients::CONTACTS]),
        );

        // When / Then
        static::assertSame([Clients::CONTACTS], $record->audience()->values);
    }

    /**
     * RFC 9068 §2.2.1
     */
    #[Test]
    public function itRefusesASessionWithoutWhatThatSessionHadProven(): void
    {
        // Given
        $client = Clients::gateway(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('keeps what that session had proven, and one that names none keeps neither');

        // When
        new StoredSubjectAccessToken(
            str_repeat('a', 64),
            Uuid::v7(),
            $client,
            new Subject('alice-subject'),
            null,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            Uuid::v7(),
            null,
            null,
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
    }

    /**
     * RFC 8693 §4.1
     */
    #[Test]
    public function itKeepsTheChainOfActorsThatHoldsIt(): void
    {
        // Given
        $actor = new Actor(new Subject('gateway'), new Actor(new Subject('first-hop')));
        $record = Tokens::storedSubjectAccessToken(
            'the-value',
            Clients::gateway(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('alice-subject'),
            Fixtures::now(),
            actor: $actor,
        );

        // When / Then
        static::assertTrue($record->actor?->equals($actor));
    }
}
