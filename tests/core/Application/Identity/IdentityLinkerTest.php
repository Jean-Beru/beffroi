<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Identity;

use Heidi\Core\Application\Identity\IdentityAlreadyLinkedException;
use Heidi\Core\Application\Identity\IdentityLinker;
use Heidi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class IdentityLinkerTest extends TestCase
{
    private const string PROVIDER = 'demo-issuer';

    private const string SUBJECT = 'alice@issuer.example';

    private Tenant $tenant;

    private User $user;

    private InMemoryLinkedIdentityRepository $identities;

    private MockClock $clock;

    private IdentityLinker $linker;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->user = Fixtures::user($this->tenant);
        $this->identities = new InMemoryLinkedIdentityRepository();
        $this->clock = new MockClock('2026-09-27T12:00:00+00:00');
        $this->linker = new IdentityLinker($this->identities, new SymfonyUuidGenerator(), $this->clock);
    }

    /**
     * Decision 0002: the row that makes a subject of an upstream provider a user of this tenant.
     */
    #[Test]
    public function itLinksAUserToASubjectOfAProviderAndSavesIt(): void
    {
        // When
        $identity = $this->linker->link($this->user, self::PROVIDER, self::SUBJECT);

        // Then
        static::assertSame($identity, $this->identities->find($this->tenant, self::PROVIDER, self::SUBJECT));
        static::assertSame($this->user, $identity->user);
        static::assertSame(self::PROVIDER, $identity->provider);
        static::assertSame(self::SUBJECT, $identity->subject);
        static::assertSame([], $identity->claims);
        static::assertEquals($this->clock->now(), $identity->linkedAt);
        static::assertEquals($this->clock->now(), $identity->lastSeenAt);
    }

    #[Test]
    public function itKeepsTheClaimsTheProviderGaveOfThatSubject(): void
    {
        // When
        $identity = $this->linker->link($this->user, self::PROVIDER, self::SUBJECT, [
            'email' => 'alice@issuer.example',
        ]);

        // Then
        static::assertSame(
            [
                'email' => 'alice@issuer.example',
            ],
            $identity->claims,
        );
    }

    /**
     * What a second run of an import does: the row is the one that was there, with what the provider says now.
     */
    #[Test]
    public function itRefreshesTheIdentityItAlreadyHasRatherThanAddingASecond(): void
    {
        // Given
        $first = $this->linker->link($this->user, self::PROVIDER, self::SUBJECT, [
            'email' => 'old@issuer.example',
        ]);
        $this->clock->sleep(60);

        // When
        $again = $this->linker->link($this->user, self::PROVIDER, self::SUBJECT, [
            'email' => 'new@issuer.example',
        ]);

        // Then
        static::assertSame($first, $again);
        static::assertSame(
            [
                'email' => 'new@issuer.example',
            ],
            $again->claims,
        );
        static::assertEquals($this->clock->now(), $again->lastSeenAt);
    }

    #[Test]
    public function itLeavesTheDateOfTheLinkAloneWhenItRefreshesIt(): void
    {
        // Given
        $linkedAt = $this->clock->now();
        $this->linker->link($this->user, self::PROVIDER, self::SUBJECT);
        $this->clock->sleep(3600);

        // When
        $again = $this->linker->link($this->user, self::PROVIDER, self::SUBJECT);

        // Then
        static::assertEquals($linkedAt, $again->linkedAt);
    }

    /**
     * Decision 0002: a subject names one user of a tenant, so moving it would hand one account the sign-ins
     * of another.
     */
    #[Test]
    public function itRefusesAnIdentityAnotherUserOfTheTenantAlreadyIs(): void
    {
        // Given
        $this->linker->link($this->user, self::PROVIDER, self::SUBJECT);
        $other = Fixtures::user($this->tenant, 'bob', 'bob-subject');

        // Then
        $this->expectException(IdentityAlreadyLinkedException::class);
        $this->expectExceptionMessageIs('The subject "alice@issuer.example" of the provider "demo-issuer" is already the user "alice" in this tenant.');

        // When
        $this->linker->link($other, self::PROVIDER, self::SUBJECT);
    }

    /**
     * The same subject at another provider is another identity: what names a user is the pair.
     */
    #[Test]
    public function itLinksTheSameSubjectAtAnotherProviderAsAnotherIdentity(): void
    {
        // Given
        $first = $this->linker->link($this->user, self::PROVIDER, self::SUBJECT);

        // When
        $second = $this->linker->link($this->user, 'another-issuer', self::SUBJECT);

        // Then
        static::assertNotSame($first, $second);
        static::assertSame($second, $this->identities->find($this->tenant, 'another-issuer', self::SUBJECT));
    }

    #[Test]
    #[DataProvider('provideEmptyNames')]
    public function itRefusesAnIdentityThatNamesNothing(string $provider, string $subject): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->linker->link($this->user, $provider, $subject);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEmptyNames(): iterable
    {
        yield 'no provider' => ['', self::SUBJECT];
        yield 'no subject' => [self::PROVIDER, ''];
    }
}
