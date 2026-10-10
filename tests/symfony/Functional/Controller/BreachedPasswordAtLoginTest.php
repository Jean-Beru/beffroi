<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use DateInterval;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use Symfony\Component\HttpFoundation\Response;

/**
 * The password already posed, looked up after the login that used it (issue #552): the one thing a login
 * orders about it, and the one moment this provider holds the password at all.
 *
 * **What a login costs is what this is about.** The lookup is a Command, so it goes to a lane and the
 * browser waits for nothing; the transports of this kernel are synchronous, where a Command is handled in
 * the request, so what is asserted here is the mark and what was asked, and that it is a Command at all is
 * the routing of the contract (MessengerContractTest).
 *
 * The list of this kernel is a fixture that names nothing until a test names one (config_test.yml): no
 * test here reaches a host.
 */
final class BreachedPasswordAtLoginTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Test]
    public function aPasswordAListCountsIsMarkedAsFoundAfterTheLoginThatUsedIt(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->names([self::PASSWORD]);

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertTrue(self::passwordOf($alice)->isBreached());
    }

    #[Test]
    public function aPasswordNoListHoldsIsMarkedAsLookedUpAndNotAsFound(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->names(['a password of somebody else']);

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertFalse(self::passwordOf($alice)->isBreached());
        static::assertNotNull(self::passwordOf($alice)->breachCheckedAt);
    }

    /**
     * Nothing of a wrong guess is sent to anybody: a refused login never reaches the moment the lookup is
     * ordered from.
     */
    #[Test]
    public function aPasswordThatDidNotVerifyIsAskedAboutNobody(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->names([self::PASSWORD]);

        // When
        $this->signInOnTheForm('alice', 'not the password of anybody');

        // Then
        static::assertSame([], self::breaches()->asked);
    }

    /**
     * A login does not ask again what was asked last month, and asks again past the delay: the lists are
     * published in batches.
     */
    #[Test]
    #[TestWith(['+1 second', false], 'a second short of the delay')]
    #[TestWith(['-1 day', true], 'a day past the delay')]
    public function aLoginAsksOnlyWhenTheCredentialIsDue(string $modification, bool $asked): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $credential = self::passwordOf($alice);
        // the moment of the last lookup, read back from now: a second short of the delay, or a day past it
        $credential->notFoundInABreach(
            self::currentSecond()->sub(new DateInterval(PasswordCredential::LOOKUP_AGAIN_AFTER))->modify($modification),
        );
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($credential);
        self::breaches()->names([self::PASSWORD]);

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertSame($asked, self::breaches()->asked !== []);
    }

    /**
     * A deployment that names no list computes nothing and orders nothing: it signs people in and asks
     * nobody.
     */
    #[Test]
    public function aDeploymentThatNamesNoListSignsThePersonInAndAsksNobody(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::breaches()->namesNothing();

        // When
        $this->signInOnTheForm('alice', self::PASSWORD);

        // Then
        static::assertSame([], self::breaches()->asked);
        static::assertNull(self::passwordOf($alice)->breachCheckedAt);
    }

    /**
     * What every other test of every suite runs as, asserted rather than assumed: the list of this kernel
     * names nothing, so no test of this repository reaches a host to ask about a password. A test that
     * wants the rule arms the fixture and the arming dies with its kernel.
     */
    #[Test]
    public function theListOfTheSuiteNamesNothingUntilATestNamesOne(): void
    {
        // When / Then
        static::assertFalse(self::breaches()->looksUp());
    }

    /**
     * Signs the user in through the form of the firewall, which is the path the digest is taken on.
     */
    private function signInOnTheForm(string $username, string $password): void
    {
        $this->browser->request('GET', '/account');
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        $this->browser->submit(
            $this->browser
                ->followRedirect()
                ->selectButton('Sign in')
                ->form([
                    '_username' => $username,
                    '_password' => $password,
                ]),
        );
    }

    private static function breaches(): BreachedPasswordsOfARecord
    {
        return self::service('test.beffroi.breached_passwords', BreachedPasswordsOfARecord::class);
    }

    private static function passwordOf(User $user): PasswordCredential
    {
        self::reload();
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        $password = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($reread, PasswordCredential::class)[0] ?? null;
        static::assertInstanceOf(PasswordCredential::class, $password);

        return $password;
    }
}
