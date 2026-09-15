<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Security;

use Heidi\Bundle\Security\SecurityUser;
use Heidi\Bundle\Security\UserChecker;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Decision 0006: the state of the account is checked after the password, never before.
 */
final class UserCheckerTest extends TestCase
{
    /**
     * The account state is checked after the password: whoever does not know the password cannot tell a
     * disabled account from a wrong password.
     */
    #[Test]
    public function aDisabledUserPassesBeforeThePassword(): void
    {
        // Given
        $user = Fixtures::user();
        $user->disable(Fixtures::now());
        $adapter = new SecurityUser($user, null);
        $checker = new UserChecker();

        // When
        $checker->checkPreAuth($adapter);

        // Then
        static::assertFalse($adapter->enabled);
    }

    #[Test]
    public function aDisabledUserIsRefusedAfterThePassword(): void
    {
        // Given
        $user = Fixtures::user();
        $user->disable(Fixtures::now());
        $adapter = new SecurityUser($user, null);
        $checker = new UserChecker();

        // When
        try {
            $checker->checkPostAuth($adapter);
            static::fail('A disabled user is refused.');
        } catch (DisabledException $exception) {
            // Then
            static::assertSame($adapter, $exception->getUser());
        }
    }

    #[Test]
    public function anEnabledUserPasses(): void
    {
        // Given
        $adapter = new SecurityUser(Fixtures::user(), null);
        $checker = new UserChecker();

        // When
        $checker->checkPreAuth($adapter);
        $checker->checkPostAuth($adapter);

        // Then
        static::assertTrue($adapter->enabled);
    }

    #[Test]
    public function aUserOfAHostApplicationIsNotItsBusiness(): void
    {
        // Given
        $user = new InMemoryUser('host', null, enabled: false);
        $checker = new UserChecker();

        // When
        $checker->checkPreAuth($user);
        $checker->checkPostAuth($user);

        // Then
        static::assertFalse($user->isEnabled());
    }
}
