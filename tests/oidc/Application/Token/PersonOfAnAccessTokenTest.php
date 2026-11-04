<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.6
 */
final class PersonOfAnAccessTokenTest extends TestCase
{
    private User $alice;

    private InMemoryUserRepository $users;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user(Fixtures::tenant());
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
    }

    /**
     * RFC 8693 §2.2.1, OIDC Core §8.1
     */
    #[Test]
    public function itNamesThePersonTheTokenSaysItIsAbout(): void
    {
        // Given
        $persons = Subjects::personOfAToken($this->users);
        $token = $this->token(new Subject('a-name-only-the-other-client-holds'), $this->alice->subject);

        // When
        $read = $persons->of($token);

        // Then
        static::assertSame($this->alice, $read);
    }

    /**
     * OIDC Core §8
     */
    #[Test]
    public function itReadsTheSubjectOfATokenThatSaysNobodyForItsClient(): void
    {
        // Given
        $persons = Subjects::personOfAToken($this->users);
        $token = $this->token($this->alice->subject, null);

        // When
        $read = $persons->of($token);

        // Then
        static::assertSame($this->alice, $read);
    }

    #[Test]
    public function itNamesNobodyForAPersonTheProviderNoLongerKeeps(): void
    {
        // Given
        $persons = Subjects::personOfAToken(new InMemoryUserRepository());
        $token = $this->token(new Subject('a-name-only-the-other-client-holds'), $this->alice->subject);

        // When
        $read = $persons->of($token);

        // Then
        static::assertNull($read);
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function itNamesNobodyForASubjectNothingResolves(): void
    {
        // Given
        $persons = Subjects::personOfAToken($this->users);
        $token = $this->token(new Subject('a-name-only-the-other-client-holds'), null);

        // When
        $read = $persons->of($token);

        // Then
        static::assertNull($read);
    }

    private function token(Subject $subject, ?Subject $person): VerifiedAccessToken
    {
        return new VerifiedAccessToken(
            Clients::public($this->alice->tenant),
            new TokenAudience([Clients::CALENDAR]),
            $subject,
            Uuid::v7(),
            new Scopes([new Scope('invoices.read')]),
            null,
            [],
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
            person: $person,
        );
    }
}
