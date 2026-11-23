<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\OfferedLogins;
use App\Security\OfferedLoginInterface;
use App\Security\PasskeyLogin;
use App\Security\PasswordLogin;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class OfferedLoginsTest extends TestCase
{
    #[Test]
    public function aTenantThatNamedNoFloorIsOfferedEveryWiredLogin(): void
    {
        // When / Then
        static::assertSame(['password', 'passkey'], self::offering()->kinds(Fixtures::tenant()));
    }

    #[Test]
    public function aTenantThatSignsItsUsersInByPasskeyIsOfferedThePasskeyAlone(): void
    {
        // When / Then
        static::assertSame(['passkey'], self::offering()->kinds(Fixtures::hardenedTenant()));
    }

    #[Test]
    public function aTenantThatAsksForHardwareIsOfferedThePasskeyToo(): void
    {
        // Given
        $tenant = Fixtures::tenant('acme', 'https://id.acme.example', new PhishingResistantHardware());

        // When / Then
        static::assertSame(['passkey'], self::offering()->kinds($tenant));
    }

    #[Test]
    public function aFloorNoWiredLoginProvesIsSaidLoudly(): void
    {
        // Given
        $offering = new OfferedLogins([new PasswordLogin()]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The tenant "acme" requires "phishing_resistant" of every login and this provider wires no login that proves it; it wires password.');

        // When
        $offering->kinds(Fixtures::hardenedTenant());
    }

    private static function offering(): OfferedLogins
    {
        return new OfferedLogins(self::logins());
    }

    /**
     * @return list<OfferedLoginInterface>
     */
    private static function logins(): array
    {
        return [new PasswordLogin(), new PasskeyLogin(new RecordingEventDispatcher())];
    }
}
