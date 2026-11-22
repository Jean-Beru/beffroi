<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Application\Key\RetirementWindow;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FixedLifetimeArtifact;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3
 */
final class RetirementWindowTest extends TestCase
{
    private Tenant $tenant;

    private DateTimeImmutable $retiringAt;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->retiringAt = new DateTimeImmutable('2026-09-15T14:00:00+00:00');
    }

    #[Test]
    public function theLongestLifetimeAmongTheKindsOfThatUseDatesTheRetirement(): void
    {
        // Given
        $window = new RetirementWindow([
            new FixedLifetimeArtifact(new DateInterval('PT10M')),
            new FixedLifetimeArtifact(new DateInterval('PT1H')),
            new FixedLifetimeArtifact(new DateInterval('PT30M')),
        ]);

        // When / Then
        static::assertEquals(
            $this->retiringAt->add(new DateInterval('PT1H')),
            $window->dueAt($this->tenant, KeyUse::Signature, $this->retiringAt),
        );
    }

    #[Test]
    public function aKindTheTenantDoesNotIssueIsIgnored(): void
    {
        // Given
        $window = new RetirementWindow([new FixedLifetimeArtifact(new DateInterval('PT10M')), new FixedLifetimeArtifact(null)]);

        // When / Then
        static::assertEquals(
            $this->retiringAt->add(new DateInterval('PT10M')),
            $window->dueAt($this->tenant, KeyUse::Signature, $this->retiringAt),
        );
    }

    #[Test]
    public function aTenantWithNothingBoundToAKeyOfThatUseGetsNoWindow(): void
    {
        // Given
        $window = new RetirementWindow([]);

        // When / Then
        static::assertEquals($this->retiringAt, $window->dueAt($this->tenant, KeyUse::Signature, $this->retiringAt));
    }

    #[Test]
    public function aKindOfTheOtherUseIsIgnored(): void
    {
        // Given
        $window = new RetirementWindow([
            new FixedLifetimeArtifact(new DateInterval('PT10M'), KeyUse::Signature),
            new FixedLifetimeArtifact(new DateInterval('PT1H'), KeyUse::Encryption),
        ]);

        // When / Then
        static::assertEquals(
            $this->retiringAt->add(new DateInterval('PT10M')),
            $window->dueAt($this->tenant, KeyUse::Signature, $this->retiringAt),
        );
    }
}
