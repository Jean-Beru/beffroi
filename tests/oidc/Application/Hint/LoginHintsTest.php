<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Hint;

use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Hint\LoginHints;
use Heidi\Oidc\Application\Hint\SubjectLoginHint;
use Heidi\Oidc\Application\Hint\UserHintInterface;
use Heidi\Oidc\Application\Hint\UsernameLoginHint;
use Heidi\Oidc\Bridge\InMemory\InMemoryPairwiseSubjectRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use Heidi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §3.1.2.1: what the "login_hint" of an authorization request names, read by the one reading
 * this provider is wired with, so that the page waiting for a login can offer a name instead of the value
 * the client carried. OIDC Core §4 is what makes it worth reading: the hint of a login this provider
 * begins at a client is a "sub" this provider wrote itself.
 */
final class LoginHintsTest extends TestCase
{
    private Client $client;

    private User $alice;

    private InMemoryUserRepository $users;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $this->client = Clients::public($tenant);
        $this->alice = Fixtures::user($tenant);
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
    }

    /**
     * OIDC Core §8: the subject this provider issued to that client, which is what §4 puts in the hint of
     * a login it begins there.
     */
    #[Test]
    public function aHintReadAsASubjectNamesItsUser(): void
    {
        // Given
        $hints = new LoginHints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * §3.1.2.1: what a login hint names is a rule of the tenant, so the same parameter read as a username
     * finds the same user by another value, and neither reading ever tries the other.
     */
    #[Test]
    public function aHintReadAsAUsernameNamesItsUser(): void
    {
        // Given
        $hints = new LoginHints([new UsernameLoginHint($this->users)]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice'));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * §3.1.2.1 makes the parameter a hint: what it fails to name costs the request nothing, and the page
     * that follows offers nothing rather than a string nobody typed.
     */
    #[Test]
    #[DataProvider('provideHintsNamingNobody')]
    public function aHintThatNamesNobodyNamesNobody(?string $value): void
    {
        // Given
        $hints = new LoginHints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: $value));

        // Then
        static::assertNull($user);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideHintsNamingNobody(): iterable
    {
        yield 'a request that carries no hint' => [null];
        yield 'a hint that carries nothing' => [''];
        yield 'a subject nobody has' => ['bob-subject'];
        yield 'a value that is no subject at all' => ["\x00"];
    }

    /**
     * A deployment that says "none" reads no hint at all, and a request that carries one is served exactly
     * as a request that carries none: the value is never tried against whatever lookup might match it.
     */
    #[Test]
    public function aHintNothingIsWiredToReadNamesNobody(): void
    {
        // Given
        $hints = new LoginHints([]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));

        // Then
        static::assertNull($user);
    }

    /**
     * §3.1.2.1: a hint is offered, so a reading that refuses the value refuses the value and not the
     * request, which would make a parameter nobody has to send able to break one.
     */
    #[Test]
    public function aReadingThatRefusesTheValueNamesNobody(): void
    {
        // Given
        $refusing = self::createStub(UserHintInterface::class);
        $refusing->method('parameterName')->willReturn(LoginHints::PARAMETER);
        $refusing->method('userNamedBy')->willThrowException(new InvalidRequestException('Not of the shape I read.'));

        // When
        $user = new LoginHints([$refusing])->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));

        // Then
        static::assertNull($user);
    }

    /**
     * Two readings of one parameter is a wiring with two answers to one question, and picking one of them
     * would be the search §3.1.2.1 never asks for.
     */
    #[Test]
    public function twoReadingsOfOneParameterAreRefused(): void
    {
        // Given
        $hints = new LoginHints([
            new SubjectLoginHint(Subjects::ofAProvider($this->users)),
            new UsernameLoginHint($this->users),
        ]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Two hints are wired to read the login_hint parameter of an authorization request; a hint is read one way.');

        // When
        $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));
    }

    /**
     * OIDC Core §8.1: the hint of a login begun at a pairwise client is the identifier of that client's
     * sector, which no row carries, and reading it back is the way in that makes §4 worth anything there.
     */
    #[Test]
    public function aPairwiseHintNamesItsUserForTheClientItWasHandedTo(): void
    {
        // Given
        $assigned = new InMemoryPairwiseSubjectRepository();
        $subjects = Subjects::bothKinds($this->users, assigned: $assigned);
        $sector = Clients::pairwise($this->alice->tenant, 'pairwise-app', 'https://rp.example/callback');
        $hints = new LoginHints([new SubjectLoginHint($subjects)]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($sector, loginHint: $subjects->resolve($this->alice, $sector)->value));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * OIDC Core §8.1, the property pairwise exists for: a "sub" a client was never handed names nobody for
     * that client, even where it names somebody for another, so a hint carried from one sector to another
     * tells the second one nothing.
     */
    #[Test]
    public function aPairwiseHintOfAnotherSectorNamesNobody(): void
    {
        // Given
        $assigned = new InMemoryPairwiseSubjectRepository();
        $subjects = Subjects::bothKinds($this->users, assigned: $assigned);
        $sector = Clients::pairwise($this->alice->tenant, 'pairwise-app', 'https://rp.example/callback');
        $other = Clients::pairwise($this->alice->tenant, 'pairwise-other-app', 'https://other.example/callback');
        $hints = new LoginHints([new SubjectLoginHint($subjects)]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($other, loginHint: $subjects->resolve($this->alice, $sector)->value));

        // Then
        static::assertNull($user);
    }
}
