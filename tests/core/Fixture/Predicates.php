<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Bridge\Session\WiredAuthenticationPredicates;
use Beffroi\Core\Domain\Session\AuthenticationPredicateInterface;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;

/**
 * Decision 0010
 */
final readonly class Predicates
{
    /**
     * @return non-empty-list<AuthenticationPredicateInterface>
     */
    public static function all(): array
    {
        return [new PhishingResistantHardware(), new PhishingResistant(), new TwoFactors(), new SingleFactor()];
    }

    public static function wired(): WiredAuthenticationPredicates
    {
        return new WiredAuthenticationPredicates(self::all());
    }
}
