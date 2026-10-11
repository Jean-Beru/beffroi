<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\OfferedLogins;
use Beffroi\Bundle\Security\OfferedLoginInterface;
use Beffroi\Bundle\Security\PasskeyLogin;
use Beffroi\Bundle\Security\PasswordLogin;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #327: what the login page of a tenant offers is the logins the firewall wires, less those whose
 * proofs the floor of that tenant never reads. The page holds a form per kind and asks this which ones to
 * show, so the kinds come from the wiring and never from the template.
 */
final class OfferedLoginsTest extends TestCase
{
    #[Test]
    public function aTenantThatNamedNoFloorIsOfferedEveryWiredLogin(): void
    {
        // When / Then
        static::assertSame(['password', 'passkey'], self::offering()->kinds(Fixtures::tenant()));
    }

    /**
     * The one #327 is about: the password is not offered, so the page holds no field to type it in and no
     * username to type it against.
     */
    #[Test]
    public function aTenantThatSignsItsUsersInByPasskeyIsOfferedThePasskeyAlone(): void
    {
        // When / Then
        static::assertSame(['passkey'], self::offering()->kinds(Fixtures::hardenedTenant()));
    }

    /**
     * A key held in hardware is what a passkey may prove, so the login stays offered: which of the two a
     * given key is, the ceremony says and the page cannot (PasskeyEnrolment).
     */
    #[Test]
    public function aTenantThatAsksForHardwareIsOfferedThePasskeyToo(): void
    {
        // Given
        $tenant = Fixtures::tenant('acme', 'https://id.acme.example', new PhishingResistantHardware());

        // When / Then
        static::assertSame(['passkey'], self::offering()->kinds($tenant));
    }

    /**
     * A floor no wired login proves is a page nobody could sign in on: it is a deployment to fix, and it
     * says what it wires rather than rendering a page with nothing on it.
     */
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
        return [new PasswordLogin(), new PasskeyLogin(new InMemoryCredentialRepository(), new RecordingEventDispatcher())];
    }
}
