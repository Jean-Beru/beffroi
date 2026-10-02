<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Exchange;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Who a token says may act for its subject (RFC 8693 §4.4).
 */
final class MayActTest extends TestCase
{
    /**
     * RFC 8693 §4.4: the same shape as "act", of which this provider writes the "sub" and nothing else.
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
     * RFC 8693 §4.4: the party named here and nobody else.
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
     * RFC 8693 §4.1: the chain is read at its outermost member, which is the one about to act; the ones
     * inside it have acted already.
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
