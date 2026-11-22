<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal;

use Beffroi\Saml2\Model\Internal\Window;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-7
 */
final class WindowTest extends TestCase
{
    /**
     * M-7
     */
    #[Test]
    public function itGivesNowPlusTheSkewAsTheLatestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T12:02:00.500000', $this->window()->latest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7
     */
    #[Test]
    public function itGivesNowMinusTheSkewAsTheEarliestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T11:58:00.500000', $this->window()->earliest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7
     */
    #[Test]
    public function itGivesNowMinusTheMessageAgeAsTheOldestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T11:50:00.500000', $this->window()->oldest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7, section 7
     */
    #[Test]
    public function itGivesNowPlusTheBearerWindowAndTheSkewAsItsLimit(): void
    {
        // When / Then
        static::assertSame('2026-09-30T12:17:00.500000', $this->window()->bearerLimit()->format('Y-m-d\TH:i:s.u'));
    }

    private function window(): Window
    {
        return new Window(
            new DateTimeImmutable('2026-09-30T12:00:00.500000Z'),
            new TimeBounds(clockSkew: 120, maxMessageAge: 600, maxBearerWindow: 900),
        );
    }
}
