<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Event\AuthenticationFailureReason;

/**
 * Decision 0006
 */
final class TheOrderOfAPasswordLogin
{
    public const string USERNAME = 'alice';

    public const string PASSWORD = 'correct horse battery staple';

    public const string WITHOUT_A_PASSWORD = 'bob';

    public const string DISABLED = 'carol';

    /**
     * @return iterable<string, array{string, string, AuthenticationFailureReason|null}>
     */
    public static function steps(): iterable
    {
        yield 'a username nobody answers to' => ['nobody', self::PASSWORD, AuthenticationFailureReason::UnknownUser];
        yield 'a person who holds no password' => [self::WITHOUT_A_PASSWORD, self::PASSWORD, AuthenticationFailureReason::NoSuchCredential];
        yield 'a wrong password' => [self::USERNAME, 'not the password of anybody', AuthenticationFailureReason::InvalidCredential];
        // The account's state is read after its password: only whoever typed the right one learns it is disabled.
        yield 'a disabled account and a wrong password' => [self::DISABLED, 'not the password of anybody', AuthenticationFailureReason::InvalidCredential];
        yield 'a disabled account and the right password' => [self::DISABLED, self::PASSWORD, AuthenticationFailureReason::DisabledUser];
        yield 'the right password' => [self::USERNAME, self::PASSWORD, null];
    }
}
