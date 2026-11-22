<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Session;

use Beffroi\Core\Bridge\Session\WiredAuthenticationPredicates;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0010
 */
final class WiredAuthenticationPredicatesTest extends TestCase
{
    #[Test]
    public function aStoredNameIsReadBackAsThePredicateTheWiringHolds(): void
    {
        // Given
        $predicates = new WiredAuthenticationPredicates([new SingleFactor(), new PhishingResistant()]);

        // When
        $predicate = $predicates->named(PhishingResistant::NAME);

        // Then
        static::assertInstanceOf(PhishingResistant::class, $predicate);
    }

    #[Test]
    public function aNameNothingWiredCarriesIsRefusedWithTheOnesThatAre(): void
    {
        // Given
        $predicates = new WiredAuthenticationPredicates([new SingleFactor(), new PhishingResistant()]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This provider defines no authentication predicate "no_password_at_all"; it defines single_factor, phishing_resistant.');

        // When
        $predicates->named('no_password_at_all');
    }

    #[Test]
    public function aPredicateWiredTwiceIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The algorithm "single_factor" is wired twice.');

        // When
        new WiredAuthenticationPredicates([new SingleFactor(), new SingleFactor()]);
    }

    #[Test]
    public function aProviderThatDefinesNoPredicateIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider defines at least one authentication predicate: every session has an "acr".');

        // When
        new WiredAuthenticationPredicates([]);
    }
}
