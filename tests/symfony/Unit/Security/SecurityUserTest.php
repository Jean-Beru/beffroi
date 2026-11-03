<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Security;

use App\Security\CorePasswordHasher;
use App\Security\SecurityUser;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Tests\Fixture\Fixtures;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §5.4, decision 0002: the adapter the security component sees, over a user of the core
 * and never over the User of another application.
 */
final class SecurityUserTest extends TestCase
{
    #[Test]
    public function theAdapterExposesTheUserAndItsHashToTheFirewall(): void
    {
        // Given
        $user = Fixtures::user();
        $hash = new PasswordHash(new Argon2id(), '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA');
        $credential = new PasswordCredential(Uuid::v7(), $user, $hash, Fixtures::now());

        // When
        $adapter = new SecurityUser($user, $credential);

        // Then
        static::assertSame('alice', $adapter->getUserIdentifier());
        static::assertTrue($adapter->id->equals($user->id));
        static::assertSame([SecurityUser::ROLE], $adapter->getRoles());
        static::assertTrue($adapter->enabled);
        static::assertSame(CorePasswordHasher::encode($hash), $adapter->getPassword());
        static::assertSame($user, $adapter->user());
        static::assertSame($credential, $adapter->passwordCredential());
    }

    #[Test]
    public function aUserWithoutAPasswordHasNoneToVerify(): void
    {
        // When
        $adapter = new SecurityUser(Fixtures::user(), null);

        // Then
        static::assertNull($adapter->getPassword());
        static::assertNull($adapter->passwordCredential());
    }

    #[Test]
    public function aDisabledUserSaysSo(): void
    {
        // Given
        $user = Fixtures::user();
        $user->disable(Fixtures::now());

        // When / Then
        static::assertFalse(new SecurityUser($user, null)->enabled);
    }

    /**
     * The token of the firewall goes to the HTTP session between two requests: the identifier, the
     * username, the state and the hash survive, the entities do not.
     */
    #[Test]
    public function theSerialisedFormHoldsNoEntity(): void
    {
        // Given
        $adapter = self::adapterOfAlice();

        // When
        $serialized = serialize($adapter);

        // Then
        static::assertStringNotContainsString('alice-subject', $serialized);
    }

    #[Test]
    public function theSerialisedFormKeepsWhatARefreshNeeds(): void
    {
        // Given
        $adapter = self::adapterOfAlice();

        // When
        $restored = unserialize(serialize($adapter));

        // Then
        static::assertInstanceOf(SecurityUser::class, $restored);
        static::assertTrue($restored->id->equals($adapter->id));
        static::assertSame('alice', $restored->getUserIdentifier());
        static::assertTrue($restored->enabled);
        static::assertSame($adapter->getPassword(), $restored->getPassword());
        static::assertTrue($restored->isEqualTo($adapter));
    }

    #[Test]
    public function aRestoredAdapterHoldsNoUser(): void
    {
        // Given
        $restored = unserialize(serialize(self::adapterOfAlice()));
        static::assertInstanceOf(SecurityUser::class, $restored);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('refresh it through the provider');

        // When
        $restored->user();
    }

    #[Test]
    public function aRestoredAdapterHoldsNoCredential(): void
    {
        // Given
        $restored = unserialize(serialize(self::adapterOfAlice()));
        static::assertInstanceOf(SecurityUser::class, $restored);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('refresh it through the provider');

        // When
        $restored->passwordCredential();
    }

    #[Test]
    public function aSerialisedFormThisClassDidNotWriteIsRefused(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The serialised user is not one this class wrote.');

        // When
        unserialize('O:25:"App\Security\SecurityUser":1:{s:2:"id";s:3:"foo";}');
    }

    /**
     * A rename does not sign the other browsers out.
     */
    #[Test]
    public function aRenamedUserIsStillEqual(): void
    {
        // Given
        $user = Fixtures::user();
        $hash = self::hash();
        $adapter = new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, $hash, Fixtures::now()));
        $user->rename('alice.renamed', Fixtures::now());

        // When / Then
        static::assertTrue($adapter->isEqualTo(new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, $hash, Fixtures::now()))));
    }

    /**
     * A password change signs the other browsers out.
     */
    #[Test]
    public function aUserWithAnotherHashIsNotEqual(): void
    {
        // Given
        $user = Fixtures::user();
        $adapter = new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, self::hash(), Fixtures::now()));
        $changed = new PasswordHash(new Argon2id(), '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$b3RoZXI');

        // When / Then
        static::assertFalse($adapter->isEqualTo(new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, $changed, Fixtures::now()))));
        static::assertFalse($adapter->isEqualTo(new SecurityUser($user, null)));
    }

    /**
     * Another user never compares equal, nor does a user of another application.
     */
    #[Test]
    #[DataProvider('provideOtherUsers')]
    public function anotherUserIsNotEqual(UserInterface $other): void
    {
        // Given
        $adapter = self::adapterOfAlice();

        // When / Then
        static::assertFalse($adapter->isEqualTo($other));
    }

    /**
     * @return iterable<string, array{UserInterface}>
     */
    public static function provideOtherUsers(): iterable
    {
        yield 'another user of the core' => [new SecurityUser(Fixtures::user(username: 'bob', subject: 'bob-subject'), null)];
        yield 'a user of another application' => [new InMemoryUser('alice', null)];
    }

    private static function hash(): PasswordHash
    {
        return new PasswordHash(new Argon2id(), '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA');
    }

    private static function adapterOfAlice(): SecurityUser
    {
        $user = Fixtures::user();

        return new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, self::hash(), Fixtures::now()));
    }
}
