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
    #[Test]
    public function aDisabledUserIsRefusedAfterThePasswordOnly(): void
    {
        $user = Fixtures::user();
        $user->disable(Fixtures::now());
        $adapter = new SecurityUser($user, null);
        $checker = new UserChecker();

        $checker->checkPreAuth($adapter);
        try {
            $checker->checkPostAuth($adapter);
            static::fail('A disabled user is refused.');
        } catch (DisabledException $exception) {
            static::assertSame($adapter, $exception->getUser());
        }
    }

    #[Test]
    public function anEnabledUserPasses(): void
    {
        $adapter = new SecurityUser(Fixtures::user(), null);
        $checker = new UserChecker();

        $checker->checkPreAuth($adapter);
        $checker->checkPostAuth($adapter);

        static::assertTrue($adapter->enabled);
    }

    #[Test]
    public function aUserOfAHostApplicationIsNotItsBusiness(): void
    {
        $user = new InMemoryUser('host', null, enabled: false);
        $checker = new UserChecker();

        $checker->checkPreAuth($user);
        $checker->checkPostAuth($user);

        static::assertFalse($user->isEnabled());
    }
}
