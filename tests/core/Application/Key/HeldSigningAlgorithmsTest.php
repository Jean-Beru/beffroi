<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\HeldSigningAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldKeys;
use Beffroi\Core\Tests\Fixture\HeldSigning;
use Beffroi\Core\Tests\Fixture\Keys;
use function array_map;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class HeldSigningAlgorithmsTest extends TestCase
{
    #[Test]
    public function aTenantSignsWithTheWiredAlgorithmsItHoldsAnActiveKeyFor(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $keys = new HeldKeys($tenant);
        $keys->active(Algorithms::es256(), self::pairOf(Algorithms::es256()));
        $keys->active(Algorithms::rs256(), Keys::pair());
        $held = new HeldSigningAlgorithms(Algorithms::all(), $keys->repository);

        // When
        $algorithms = $held->of($tenant);

        // Then
        static::assertSame(['RS256', 'ES256'], array_map(static fn ($algorithm): string => $algorithm->name(), $algorithms));
    }

    #[Test]
    public function aKeyStagedOrRetiredIsNoKeyToSignWith(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $keys = new HeldKeys($tenant);
        $keys->staged(Algorithms::rs256(), Keys::pair());
        $keys->retired(Algorithms::rs256(), Keys::otherPair());
        $held = new HeldSigningAlgorithms(Algorithms::all(), $keys->repository);

        // When
        $holds = $held->holds($tenant, Algorithms::rs256());

        // Then
        static::assertFalse($holds);
    }

    #[Test]
    public function theKeyOfAnotherTenantIsNoKeyOfThisOne(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant('globex'));
        $keys->active(Algorithms::rs256(), Keys::pair());
        $held = new HeldSigningAlgorithms(Algorithms::all(), $keys->repository);

        // When
        $holds = $held->holds(Fixtures::tenant(), Algorithms::rs256());

        // Then
        static::assertFalse($holds);
    }

    #[Test]
    public function theDefaultAlgorithmIsOfferedOnlyWithItsKey(): void
    {
        // Given
        $held = HeldSigning::of([Algorithms::rs256()], new JoseSignatureAlgorithms([Algorithms::es256(), Algorithms::rs256()]));

        // When
        $default = $held->defaultOf(Fixtures::tenant());

        // Then
        static::assertSame([], $default);
    }

    private static function pairOf(SignatureAlgorithmInterface $algorithm): GeneratedKeyPair
    {
        return new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate($algorithm);
    }
}
