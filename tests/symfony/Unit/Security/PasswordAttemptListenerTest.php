<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Security;

use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Bundle\Security\PasswordAttemptListener;
use Heidi\Bundle\Security\RefusalCost;
use Heidi\Bundle\Security\SecurityUser;
use Heidi\Core\Application\Authentication\DecoyHash;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Tests\Fixture\FakeAttemptLimiter;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0006 and architecture §5.4: an attempt too many is refused before the hash and costs the
 * decoy hash of the core, as in PasswordAuthenticator.
 */
final class PasswordAttemptListenerTest extends TestCase
{
    private FakePasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new FakePasswordHasher();
    }

    #[Test]
    public function aRefusedAttemptPaysTheDecoyHash(): void
    {
        // Given
        $listener = new PasswordAttemptListener(new FakeAttemptLimiter(0), new RefusalCost(new DecoyHash($this->hasher, new SymfonyUuidGenerator())));
        $event = self::event();

        // When
        try {
            $listener->onCheckPassport($event);
        } catch (TooManyLoginAttemptsAuthenticationException) {
        }

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertNotSame($this->hasher->hash('correct horse')->encoded, $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function aRefusedAttemptIsRefusedAsTooManyAttempts(): void
    {
        // Given
        $listener = new PasswordAttemptListener(new FakeAttemptLimiter(0), new RefusalCost(new DecoyHash($this->hasher, new SymfonyUuidGenerator())));
        $event = self::event();

        // Then
        $this->expectException(TooManyLoginAttemptsAuthenticationException::class);

        // When
        $listener->onCheckPassport($event);
    }

    /**
     * The hash of the user is the one CheckCredentialsListener will verify.
     */
    #[Test]
    public function anAllowedAttemptPaysNothing(): void
    {
        // Given
        $listener = new PasswordAttemptListener(new FakeAttemptLimiter(5), new RefusalCost(new DecoyHash($this->hasher, new SymfonyUuidGenerator())));
        $event = self::event();

        // When
        $listener->onCheckPassport($event);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    private static function event(): CheckPassportEvent
    {
        $user = Fixtures::user();
        $credential = new PasswordCredential(Uuid::v7(), $user, new FakePasswordHasher()->hash('correct horse'), Fixtures::now());
        $badge = new UserBadge('alice', static fn (): SecurityUser => new SecurityUser($user, $credential));

        return new CheckPassportEvent(static::createStub(AuthenticatorInterface::class), new Passport($badge, new PasswordCredentials('correct horse')));
    }
}
