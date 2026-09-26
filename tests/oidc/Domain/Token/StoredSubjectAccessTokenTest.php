<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Exchange\Actor;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\StoredSubjectAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Uid\Uuid;

/**
 * The record of an opaque access token whose subject was named by what the client presented
 * (RFC 8693 §2.1, RFC 7523 §2.1, architecture §4.6).
 */
final class StoredSubjectAccessTokenTest extends TestCase
{
    /**
     * RFC 9068 §2.2.1: the sign-in the presented token named, read back as the pair the issuers write.
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
     * RFC 6749 §4.4: a record that names no session names no sign-in either.
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
     * RFC 8707 §2: the token is addressed to the resources the request named, which its introspection renders.
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
     * RFC 9068 §2.2.1: half of a sign-in was never written here.
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
     * RFC 8693 §4.1: the chain of actors as it was written.
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
