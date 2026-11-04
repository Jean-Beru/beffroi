<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DecoyHashTest extends TestCase
{
    private FakePasswordHasher $hasher;

    private DecoyHash $decoy;

    protected function setUp(): void
    {
        $this->hasher = new FakePasswordHasher();
        $this->decoy = new DecoyHash($this->hasher, new SymfonyUuidGenerator());
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function itPaysOneVerificationAgainstAHashOfTheHasher(): void
    {
        // When
        $this->decoy->verify('whatever');

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertStringStartsWith('fake:', $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function theDecoyIsNotTheHashOfThePassword(): void
    {
        // When
        $this->decoy->verify('whatever');

        // Then
        static::assertNotSame($this->hasher->hash('whatever')->encoded, $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function theSameDecoyServesEveryVerification(): void
    {
        // When
        $this->decoy->verify('first');
        $this->decoy->verify('second');

        // Then
        static::assertCount(2, $this->hasher->verifiedAgainst);
        static::assertSame($this->hasher->verifiedAgainst[0], $this->hasher->verifiedAgainst[1]);
    }
}
