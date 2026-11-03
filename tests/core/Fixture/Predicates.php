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
 * The authentication predicates the tests wire (decision 0010): the four the provider wires, in the order
 * it wires them, strongest first, which is the order the default policy of the core answers in.
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
