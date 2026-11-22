<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyFamily;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakeSignatureAlgorithm;
use DateInterval;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3
 */
final class KeyFamiliesTest extends TestCase
{
    #[Test]
    public function anAlgorithmRotatesByTheScheduleOfItsFamily(): void
    {
        // Given
        $signing = new RotationSchedule(new DateInterval('PT6M'), new DateInterval('P90D'));
        $encryption = new RotationSchedule(new DateInterval('P7D'), new DateInterval('P365D'));
        $families = new JoseKeyAlgorithms([
            new JoseKeyFamily(Algorithms::all(), $signing),
            new JoseKeyFamily(Algorithms::keyEncryption(), $encryption),
        ]);

        // When
        $schedule = $families->of(Algorithms::ecdhEsA256Kw());

        // Then
        static::assertSame($encryption, $schedule);
    }

    #[Test]
    public function anAlgorithmNoFamilyHoldsIsRefused(): void
    {
        // Given
        $families = Algorithms::readAsOne([Algorithms::all()]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('No family of keys holds the algorithm "ES256UNWIRED": it is wired with no staging delay and no age to rotate by.');

        // When
        $families->of(new FakeSignatureAlgorithm());
    }
}
