<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Security;

use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Bundle\Security\DecoyHashListener;
use Heidi\Bundle\Security\RefusalCost;
use Heidi\Bundle\Security\SecurityUser;
use Heidi\Core\Application\Authentication\DecoyHash;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0006 and architecture §5.4: the two refusals Symfony makes before any hash, an unknown
 * username and a user without a password, cost the decoy hash of the core on the firewall, as in
 * PasswordAuthenticator.
 */
final class DecoyHashListenerTest extends TestCase
{
    private FakePasswordHasher $hasher;

    private DecoyHashListener $listener;

    protected function setUp(): void
    {
        $this->hasher = new FakePasswordHasher();
        $this->listener = new DecoyHashListener(new RefusalCost(new DecoyHash($this->hasher, new SymfonyUuidGenerator())));
    }

    #[Test]
    public function anUnknownUserPaysTheDecoyHash(): void
    {
        // Given
        $event = self::event(new Passport(self::nobody(), new PasswordCredentials('whatever')));

        // When
        try {
            $this->listener->onUnknownUser($event);
        } catch (UserNotFoundException) {
        }

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertNotSame($this->hasher->hash('whatever')->encoded, $this->hasher->verifiedAgainst[0]);
    }

    /**
     * The exception of the provider goes on as it came: the manager hides it as bad credentials.
     */
    #[Test]
    public function anUnknownUserIsStillUnknown(): void
    {
        // Given
        $event = self::event(new Passport(self::nobody(), new PasswordCredentials('whatever')));

        // Then
        $this->expectException(UserNotFoundException::class);

        // When
        $this->listener->onUnknownUser($event);
    }

    #[Test]
    public function aKnownUserPaysNothingBeforeTheChecker(): void
    {
        // Given
        $event = self::event(new Passport(self::alice(true), new PasswordCredentials('whatever')));

        // When
        $this->listener->onUnknownUser($event);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    /**
     * A passkey names nobody until its assertion is verified; its refusals are the authenticator's.
     */
    #[Test]
    public function aPassportWithoutAPasswordIsNotConcerned(): void
    {
        // Given
        $event = self::event(new SelfValidatingPassport(self::nobody()));

        // When
        $this->listener->onUnknownUser($event);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function aUserWithoutAPasswordPaysTheDecoyHash(): void
    {
        // Given
        $event = self::event(new Passport(self::alice(false), new PasswordCredentials('whatever')));

        // When
        $this->listener->onMissingPassword($event);

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertNotSame($this->hasher->hash('whatever')->encoded, $this->hasher->verifiedAgainst[0]);
    }

    /**
     * The hash of the user is the one CheckCredentialsListener will verify.
     */
    #[Test]
    public function aUserWithAPasswordPaysNothingBeforeTheHash(): void
    {
        // Given
        $event = self::event(new Passport(self::alice(true), new PasswordCredentials('whatever')));

        // When
        $this->listener->onMissingPassword($event);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    private static function nobody(): UserBadge
    {
        return new UserBadge('nobody', static function (): never {
            $exception = new UserNotFoundException();
            $exception->setUserIdentifier('nobody');

            throw $exception;
        });
    }

    private static function alice(bool $withPassword): UserBadge
    {
        $user = Fixtures::user();
        $credential = $withPassword ? new PasswordCredential(Uuid::v7(), $user, new FakePasswordHasher()->hash('correct horse'), Fixtures::now()) : null;

        return new UserBadge('alice', static fn (): SecurityUser => new SecurityUser($user, $credential));
    }

    private static function event(Passport $passport): CheckPassportEvent
    {
        return new CheckPassportEvent(static::createStub(AuthenticatorInterface::class), $passport);
    }
}
