<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Exchange;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8693 §4.4
 */
final class MayActTest extends TestCase
{
    /**
     * RFC 8693 §4.4
     */
    #[Test]
    public function itIsWrittenAsTheSubjectItNames(): void
    {
        // When / Then
        static::assertSame(
            [
                'sub' => 'gateway',
            ],
            new MayAct(new Subject('gateway'))->toClaim(),
        );
    }

    /**
     * RFC 8693 §4.4
     */
    #[Test]
    public function itAllowsThePartyItNames(): void
    {
        // When / Then
        static::assertTrue(new MayAct(new Subject('gateway'))->allows(new Actor(new Subject('gateway'))));
    }

    #[Test]
    public function itAllowsNobodyElse(): void
    {
        // When / Then
        static::assertFalse(new MayAct(new Subject('gateway'))->allows(new Actor(new Subject('somebody-else'))));
    }

    /**
     * RFC 8693 §4.1
     */
    #[Test]
    public function itReadsTheChainAtItsOutermostActor(): void
    {
        // Given
        $chain = new Actor(new Subject('backend'), new Actor(new Subject('gateway')));

        // When / Then
        static::assertFalse(new MayAct(new Subject('gateway'))->allows($chain));
    }

    #[Test]
    public function twoOfThemAreTheSameWhenTheyNameTheSameParty(): void
    {
        // When / Then
        static::assertTrue(new MayAct(new Subject('gateway'))->equals(new MayAct(new Subject('gateway'))));
    }

    #[Test]
    public function twoOfThemDifferWhenTheyNameDifferentParties(): void
    {
        // When / Then
        static::assertFalse(new MayAct(new Subject('gateway'))->equals(new MayAct(new Subject('backend'))));
    }
}
