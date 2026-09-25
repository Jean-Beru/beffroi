<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Security;

use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Bundle\Security\RefusalCost;
use Heidi\Core\Application\Authentication\DecoyHash;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Decision 0006 and architecture §5.4: a password the firewall refuses before any hash costs the decoy
 * hash of the core, unless Symfony would have refused it before any hash for a known user too.
 */
final class RefusalCostTest extends TestCase
{
    private FakePasswordHasher $hasher;

    private RefusalCost $cost;

    protected function setUp(): void
    {
        $this->hasher = new FakePasswordHasher();
        $this->cost = new RefusalCost(new DecoyHash($this->hasher, new SymfonyUuidGenerator()));
    }

    #[Test]
    public function aPasswordPaysTheDecoyHash(): void
    {
        // Given
        $passport = self::passport(new PasswordCredentials('wrong'));

        // When
        $this->cost->pay($passport);

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertNotSame($this->hasher->hash('wrong')->encoded, $this->hasher->verifiedAgainst[0]);
    }

    /**
     * CheckCredentialsListener refuses an empty password before any hash, for a known user: the decoy
     * would make an unknown one slower.
     */
    #[Test]
    public function anEmptyPasswordPaysNothing(): void
    {
        // Given
        $passport = self::passport(new PasswordCredentials(''));

        // When
        $this->cost->pay($passport);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    /**
     * A passkey and a code carry no password.
     */
    #[Test]
    public function aPassportWithoutAPasswordPaysNothing(): void
    {
        // Given
        $passport = new SelfValidatingPassport(new UserBadge('alice', static fn (): InMemoryUser => new InMemoryUser('alice', null)));

        // When
        $this->cost->pay($passport);

        // Then
        static::assertSame([], $this->hasher->verifiedAgainst);
    }

    private static function passport(PasswordCredentials $credentials): Passport
    {
        return new Passport(new UserBadge('alice', static fn (): InMemoryUser => new InMemoryUser('alice', null)), $credentials);
    }
}
