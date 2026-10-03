<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Tenant;

use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class TenantFactoryTest extends TestCase
{
    /**
     * Architecture §5.1: the tenant is the configuration; RFC 9562 §5.5 gives it a stable identifier from
     * its slug, the same in every process.
     */
    #[Test]
    public function theTenantIsBuiltFromTheConfiguration(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test/idp', 'main', 'Main tenant', new MockClock(Fixtures::now()));

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame('https://op.test/idp', (string) $tenant->issuer);
        static::assertSame('main', $tenant->slug);
        static::assertSame('Main tenant', $tenant->name);
        static::assertEquals(Fixtures::now(), $tenant->createdAt);
    }

    /**
     * Issue #449: what the pages show of the tenant is the configuration's too, read into the value
     * object that refuses a colour a style attribute must not carry.
     */
    #[Test]
    public function theTenantCarriesTheConfiguredLook(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), look: [
            'logo_uri' => 'https://acme.example/logo.svg',
            'primary_color' => '#1b4b8f',
            'primary_content_color' => '#ffffff',
        ]);

        // When
        $look = $factory->create()->look;

        // Then
        static::assertSame('https://acme.example/logo.svg', $look->logoUri?->value);
        static::assertSame('#1b4b8f', $look->primaryColor);
        static::assertSame('#ffffff', $look->primaryContentColor);
    }

    /**
     * A deployment that declares no look is served the pages it has always been served.
     */
    #[Test]
    public function aConfigurationThatDeclaresNoLookGivesTheTenantNone(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), look: [
            'logo_uri' => null,
            'primary_color' => null,
            'primary_content_color' => null,
        ]);

        // When / Then
        static::assertFalse($factory->create()->look->isDeclared());
    }

    #[Test]
    public function aLogoTheConfigurationNamesWronglyRefusesTheStart(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), look: [
            'logo_uri' => 'logo.svg',
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not an absolute URL');

        // When
        $factory->create();
    }

    /**
     * Decision 0010: the tenant carries the configured classes in their order; a name that is a number
     * in the configuration is a name.
     */
    #[Test]
    public function theTenantCarriesTheConfiguredAuthenticationClasses(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), [
            'urn:okta:loa:2fa:any' => 'two_factors',
            1 => 'single_factor',
        ]);

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame(['urn:okta:loa:2fa:any', '1'], $tenant->authenticationContextPolicy->names());
        static::assertSame(AuthenticationPredicate::TwoFactors, $tenant->authenticationContextPolicy->classes[0]->predicate);
    }

    /**
     * Decisions 0006 and 0010: what a policy may not say refuses the start, not a request.
     */
    #[Test]
    public function aPolicyTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), [
            'phr' => 'single_factor',
            '1' => 'single_factor',
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('"phr" is a registered name');

        // When
        $factory->create();
    }

    /**
     * RFC 9562 §5.5: the identifier comes from the slug, the same in every process.
     */
    #[Test]
    public function theIdentifierIsStableAcrossProcessesAndIssuers(): void
    {
        // Given
        $clock = new MockClock(Fixtures::now());

        // When
        $tenant = new TenantFactory('https://op.test/idp', 'main', 'Main tenant', $clock)->create();
        $again = new TenantFactory('https://other.test', 'main', null, $clock)->create();

        // Then
        static::assertTrue($tenant->id->equals(TenantFactory::identifier('main')));
        static::assertTrue($tenant->equals($again));
        static::assertFalse($tenant->id->equals(TenantFactory::identifier('other')));
    }

    #[Test]
    public function theNameDefaultsToTheHostOfTheIssuer(): void
    {
        // Given
        $factory = new TenantFactory('https://other.test', 'main', null, new MockClock());

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame('other.test', $tenant->name);
    }

    #[Test]
    public function anIssuerTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test/', 'main', null, new MockClock());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $factory->create();
    }

    #[Test]
    public function aSlugTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'Not A Slug', null, new MockClock());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $factory->create();
    }
}
