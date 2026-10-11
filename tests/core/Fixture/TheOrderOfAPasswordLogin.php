<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Event\AuthenticationFailureReason;

/**
 * The order a login by password is played in, named once (issue #130).
 *
 * This provider has two paths into a password: the use case of the core (PasswordAuthenticator) and the
 * firewall of the bundle, whose authenticator hands the request to the same verification. Both play the
 * steps below, in this order, and a test of each asks them of its own path: a step added to one path and
 * not to the other is a case here that one of the two answers differently.
 *
 * Each case is what is typed and what the provider announces of it. **Every one of them pays exactly one
 * hash verification** (decision 0006): the steps that refuse before the password of the user could be read
 * pay the decoy hash (DecoyHash), and the steps that read it pay for it by reading it, so the time a
 * refusal takes says nothing about the account behind it.
 */
final class TheOrderOfAPasswordLogin
{
    /**
     * The person who signs in, who holds a password and nothing else.
     */
    public const string USERNAME = 'alice';

    public const string PASSWORD = 'correct horse battery staple';

    /**
     * A person of the same tenant who holds no password at all.
     */
    public const string WITHOUT_A_PASSWORD = 'bob';

    /**
     * A person whose account this provider no longer lets in.
     */
    public const string DISABLED = 'carol';

    /**
     * @return iterable<string, array{string, string, AuthenticationFailureReason|null}>
     */
    public static function steps(): iterable
    {
        yield 'a username nobody answers to' => ['nobody', self::PASSWORD, AuthenticationFailureReason::UnknownUser];
        yield 'a person who holds no password' => [self::WITHOUT_A_PASSWORD, self::PASSWORD, AuthenticationFailureReason::NoSuchCredential];
        yield 'a wrong password' => [self::USERNAME, 'not the password of anybody', AuthenticationFailureReason::InvalidCredential];
        // after the password on purpose: a disabled account answers like a wrong password, so the account
        // is refused for the password it was given when that one is wrong, and for being disabled when it
        // was right; a provider that read the state of the account first would answer the state to both
        yield 'a disabled account and a wrong password' => [self::DISABLED, 'not the password of anybody', AuthenticationFailureReason::InvalidCredential];
        yield 'a disabled account and the right password' => [self::DISABLED, self::PASSWORD, AuthenticationFailureReason::DisabledUser];
        yield 'the right password' => [self::USERNAME, self::PASSWORD, null];
    }
}
