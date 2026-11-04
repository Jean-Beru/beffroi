<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Doctrine\Repository\DoctrineReplayStore;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;

/**
 * beffroi/saml spec/saml.md S-23, model.md M-11
 */
final class DoctrineReplayStoreTest extends DatabaseTestCase
{
    private const string ISSUER = 'https://sp.example.org/saml';

    private MockClock $clock;

    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = new MockClock(self::now());
    }

    /**
     * S-23, M-11
     */
    #[Test]
    public function aMessageWhoseWindowHasClosedIsRememberedAgain(): void
    {
        // Given
        $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', self::endOfWindow());
        $this->clock->modify('+481 seconds');

        // When
        $remembered = $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', $this->clock->now()->modify('+480 seconds'));

        // Then
        static::assertTrue($remembered);
    }

    /**
     * S-23
     */
    #[Test]
    public function aMessageWhoseWindowIsStillOpenSurvivesTheDeletion(): void
    {
        // Given
        $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', self::endOfWindow());
        $this->clock->modify('+479 seconds');

        // When
        $remembered = $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', self::endOfWindow());

        // Then
        static::assertFalse($remembered);
    }

    /**
     * S-23
     */
    private static function endOfWindow(): DateTimeImmutable
    {
        return self::now()->modify('+480 seconds');
    }

    private function store(): DoctrineReplayStore
    {
        return new DoctrineReplayStore(self::managers(), $this->clock);
    }
}
