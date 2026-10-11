<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Security;

use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Security\AcceptedPasswordListener;
use Beffroi\Bundle\Security\SecurityUser;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #571, architecture §5.4: the password the firewall accepted is an act, as the one
 * PasswordAuthenticator verifies itself is. On the firewall the hash is verified by Symfony's own form
 * login, so this is where that act is written or it is written nowhere.
 */
final class AcceptedPasswordListenerTest extends TestCase
{
    private RecordingEventDispatcher $events;

    private AcceptedPasswordListener $listener;

    protected function setUp(): void
    {
        $this->events = new RecordingEventDispatcher();
        $this->listener = new AcceptedPasswordListener(new RequestContextFactory(new MockClock(Fixtures::now())), $this->events);
    }

    #[Test]
    public function aPasswordTheFirewallAcceptedIsAnnounced(): void
    {
        // Given
        $credential = self::credential();

        // When
        $this->listener->onLoginSuccess(self::event($credential, new PasswordCredentials('correct horse')));

        // Then
        static::assertCount(1, $this->events->of(PasswordUsed::class));
        static::assertSame($credential, $this->events->of(PasswordUsed::class)[0]->credential);
    }

    /**
     * What the request carried of where it came from, as every act of this provider carries it
     * (architecture §3.5), and the moment it was accepted.
     */
    #[Test]
    public function theActSaysWhenItHappenedAndWhereItCameFrom(): void
    {
        // When
        $this->listener->onLoginSuccess(self::event(self::credential(), new PasswordCredentials('correct horse')));

        // Then
        $used = $this->events->of(PasswordUsed::class)[0];
        static::assertSame('192.0.2.7', $used->context->ipAddress);
        static::assertEquals(Fixtures::now(), $used->occurredAt);
    }

    /**
     * A passkey and a code carry no password: what they prove is their own act, announced where they are
     * verified.
     */
    #[Test]
    public function aLoginThatProvedNoPasswordAnnouncesNothing(): void
    {
        // When
        $this->listener->onLoginSuccess(self::event(self::credential(), null));

        // Then
        static::assertSame([], $this->events->events);
    }

    /**
     * Nothing of this person was accepted: there is no credential the act would name.
     */
    #[Test]
    public function aUserWhoHoldsNoPasswordAnnouncesNothing(): void
    {
        // When
        $this->listener->onLoginSuccess(self::event(null, new PasswordCredentials('correct horse')));

        // Then
        static::assertSame([], $this->events->events);
    }

    private static function credential(): PasswordCredential
    {
        return new PasswordCredential(Uuid::v7(), Fixtures::user(), new FakePasswordHasher()->hash('correct horse'), Fixtures::now());
    }

    /**
     * A login of the firewall as it reaches a listener: the user it loaded, the password it verified when
     * it verified one, and the request it came in.
     */
    private static function event(?PasswordCredential $credential, ?PasswordCredentials $password): LoginSuccessEvent
    {
        $user = new SecurityUser($credential->user ?? Fixtures::user(), $credential);
        $badge = new UserBadge('alice', static fn (): SecurityUser => $user);

        return new LoginSuccessEvent(
            static::createStub(AuthenticatorInterface::class),
            $password === null ? new SelfValidatingPassport($badge) : new Passport($badge, $password),
            static::createStub(TokenInterface::class),
            new Request(server: [
                'REMOTE_ADDR' => '192.0.2.7',
            ]),
            null,
            'beffroi_interaction',
        );
    }
}
