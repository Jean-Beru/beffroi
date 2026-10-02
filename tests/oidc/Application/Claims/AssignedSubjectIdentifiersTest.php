<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\AssignedSubjectIdentifiers;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §8: the kinds of "sub" a provider assigns are the resolvers it is wired with, and nothing is
 * kept beside them to say so.
 */
final class AssignedSubjectIdentifiersTest extends TestCase
{
    #[Test]
    public function itNamesTheKindsItIsWiredWithInTheOrderTheyAreWired(): void
    {
        // When
        $assigned = Subjects::bothKinds()->assignedSubjectTypes();

        // Then
        static::assertSame(['public', 'pairwise'], $assigned);
    }

    /**
     * A deployment that wires no pairwise resolver announces "public" alone, and there is no second place
     * to remember to change.
     */
    #[Test]
    public function aProviderWiredWithOneKindNamesThatOne(): void
    {
        // When
        $assigned = Subjects::ofAProvider()->assignedSubjectTypes();

        // Then
        static::assertSame(['public'], $assigned);
    }

    /**
     * OIDC Registration §2: the kind the client registered says who assigns its identifier.
     */
    #[Test]
    public function aClientIsAnsweredByTheKindItRegistered(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $users = new InMemoryUserRepository();
        $users->save($user);
        $subjects = Subjects::bothKinds($users);

        // When
        $public = $subjects->resolve($user, Clients::native($tenant));
        $pairwise = $subjects->resolve($user, Clients::pairwise($tenant));

        // Then
        static::assertSame($user->subject->value, $public->value);
        static::assertNotSame($user->subject->value, $pairwise->value);
    }

    /**
     * OIDC Registration §2: a client that registers no kind takes the first wired one, which is what makes
     * "public" what a client gets by writing nothing.
     */
    #[Test]
    public function aClientThatRegisteredNoKindTakesTheFirstWiredOne(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);

        // When
        $subject = Subjects::bothKinds()->resolve($user, Clients::native($tenant));

        // Then
        static::assertSame($user->subject->value, $subject->value);
    }

    /**
     * The way back goes through the same kind, so that a "sub" is read as what it is to the client that
     * presented it.
     */
    #[Test]
    public function aPresentedIdentifierIsReadByTheKindOfTheClientThatPresentedIt(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $users = new InMemoryUserRepository();
        $users->save($user);
        $subjects = Subjects::bothKinds($users);
        $client = Clients::pairwise($tenant);
        $pairwise = $subjects->resolve($user, $client);

        // When
        $found = $subjects->findUser($client, $pairwise);
        $asPublic = $subjects->findUser(Clients::native($tenant), $pairwise);

        // Then
        static::assertSame($user, $found);
        static::assertNull($asPublic);
    }

    /**
     * A wiring where the identifier a client receives depends on an order nobody wrote down is refused
     * rather than resolved by whichever resolver came first.
     */
    #[Test]
    public function itRefusesTwoResolversOfTheSameKind(): void
    {
        // Given
        $subjects = new AssignedSubjectIdentifiers([Subjects::publicKind(), Subjects::publicKind()]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Two resolvers assign a "public" subject identifier.');

        // When
        $subjects->assignedSubjectTypes();
    }

    #[Test]
    public function itRefusesAProviderWiredWithNoKindAtAll(): void
    {
        // Given
        $subjects = new AssignedSubjectIdentifiers([]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider assigns its subject identifiers in at least one kind.');

        // When
        $subjects->assignedSubjectTypes();
    }

    /**
     * A deployment that unwires a kind its clients still name is a wiring that no longer holds, and it says
     * so rather than answering with an identifier of another kind.
     */
    #[Test]
    public function itRefusesAClientWhoseKindIsNoLongerWired(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $subjects = Subjects::ofAProvider();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('No resolver assigns a "pairwise" subject identifier; the wired kinds are public.');

        // When
        $subjects->resolve(Fixtures::user($tenant), Clients::pairwise($tenant));
    }
}
