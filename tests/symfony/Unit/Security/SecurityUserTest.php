<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Security;

use Heidi\Bundle\Security\CorePasswordHasher;
use Heidi\Bundle\Security\SecurityUser;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Tests\Fixture\Fixtures;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §5.4, decision 0002: the adapter the security component sees, over a user of the core
 * and never over the User of a host application.
 */
final class SecurityUserTest extends TestCase
{
    #[Test]
    public function theAdapterExposesTheUserAndItsHashToTheFirewall(): void
    {
        $user = Fixtures::user();
        $hash = new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA');
        $credential = new PasswordCredential(Uuid::v7(), $user, $hash, Fixtures::now());

        $adapter = new SecurityUser($user, $credential);

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
        $adapter = new SecurityUser(Fixtures::user(), null);

        static::assertNull($adapter->getPassword());
        static::assertNull($adapter->passwordCredential());
    }

    #[Test]
    public function aDisabledUserSaysSo(): void
    {
        $user = Fixtures::user();
        $user->disable(Fixtures::now());

        static::assertFalse(new SecurityUser($user, null)->enabled);
    }

    /**
     * The token of the firewall goes to the HTTP session between two requests: the identifier, the
     * username, the state and the hash survive, the entities do not.
     */
    #[Test]
    public function theSerialisedFormKeepsWhatARefreshNeedsAndNoEntity(): void
    {
        $user = Fixtures::user();
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$04$abcdefghijklmnopqrstuu'), Fixtures::now());
        $adapter = new SecurityUser($user, $credential);

        $serialized = serialize($adapter);
        static::assertStringNotContainsString('alice-subject', $serialized, 'The entities are not serialised.');
        $restored = unserialize($serialized);

        static::assertInstanceOf(SecurityUser::class, $restored);
        static::assertTrue($restored->id->equals($user->id));
        static::assertSame('alice', $restored->getUserIdentifier());
        static::assertTrue($restored->enabled);
        static::assertSame($adapter->getPassword(), $restored->getPassword());
        static::assertTrue($restored->isEqualTo($adapter));
        try {
            $restored->user();
            static::fail('A restored adapter holds no user.');
        } catch (LogicException $exception) {
            static::assertStringContainsString('refresh it through the provider', $exception->getMessage());
        }
        try {
            $restored->passwordCredential();
            static::fail('A restored adapter holds no credential.');
        } catch (LogicException $exception) {
            static::assertStringContainsString('refresh it through the provider', $exception->getMessage());
        }
    }

    #[Test]
    public function aSerialisedFormThisClassDidNotWriteIsRefused(): void
    {
        try {
            unserialize('O:34:"Heidi\Bundle\Security\SecurityUser":1:{s:2:"id";s:3:"foo";}');
            static::fail('A forged form is refused.');
        } catch (LogicException $exception) {
            static::assertSame('The serialised user is not one this class wrote.', $exception->getMessage());
        }
    }

    /**
     * A password change signs the other browsers out, a rename does not, another user never compares
     * equal, nor does a user of a host application.
     */
    #[Test]
    public function equalityIsTheIdentifierAndTheHash(): void
    {
        $user = Fixtures::user();
        $hash = new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA');
        $adapter = new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, $hash, Fixtures::now()));

        $user->rename('alice.renamed', Fixtures::now());
        static::assertTrue($adapter->isEqualTo(new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, $hash, Fixtures::now()))));

        $changed = new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$b3RoZXI');
        static::assertFalse($adapter->isEqualTo(new SecurityUser($user, new PasswordCredential(Uuid::v7(), $user, $changed, Fixtures::now()))));
        static::assertFalse($adapter->isEqualTo(new SecurityUser($user, null)));
        static::assertFalse($adapter->isEqualTo(new SecurityUser(Fixtures::user(username: 'bob', subject: 'bob-subject'), null)));
        static::assertFalse($adapter->isEqualTo(new InMemoryUser('alice', null)));
    }
}
