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
 * The person a resource of the provider reads off an access token (issue #601, architecture §4.6): the one
 * the token names where whatever read it resolved one, and the "sub" read for the client the token was
 * written for where it did not.
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
     * RFC 8693 §2.2.1, OIDC Core §8.1: the "sub" of an exchanged token was written for the client that
     * presented it and names nobody to the client that asked, so the person is read by the name their
     * account carries and that "sub" is asked of nobody.
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
     * OIDC Core §8: a token that says nobody carries its own claims and nothing else, so its "sub" is read
     * for the client it was written for, which is what a public kind reads as the identifier the provider
     * keeps.
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

    /**
     * A person the provider no longer keeps is named by nobody, which the resource that asked reads as a
     * token it has nothing to answer for.
     */
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
     * A "sub" no kind of this provider resolves names nobody, which is what the "sub" of one client is to
     * another under a pairwise kind (OIDC Core §8.1).
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
