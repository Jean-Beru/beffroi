<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Tenant;

use App\Identity\WiredClaims;
use App\Tenant\TenantFactory;
use Beffroi\Core\Domain\Identity\Claim\Nickname;
use Beffroi\Core\Domain\Identity\Claim\PictureUrl;
use Beffroi\Core\Domain\Identity\Claim\ProfileUrl;
use Beffroi\Core\Domain\Identity\Claim\WebsiteUrl;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Predicates;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class TenantFactoryTest extends TestCase
{
    /**
     * Architecture §5.1, RFC 9562 §5.5
     */
    #[Test]
    public function theTenantIsBuiltFromTheConfiguration(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', 'Main tenant', new MockClock(Fixtures::now()), Predicates::wired());

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame('https://op.test', (string) $tenant->issuer);
        static::assertSame('main', $tenant->slug);
        static::assertSame('Main tenant', $tenant->name);
        static::assertEquals(Fixtures::now(), $tenant->createdAt);
    }

    #[Test]
    public function theTenantCarriesTheConfiguredLook(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), Predicates::wired(), look: [
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

    #[Test]
    public function aConfigurationThatDeclaresNoLookGivesTheTenantNone(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), Predicates::wired(), look: [
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
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), Predicates::wired(), look: [
            'logo_uri' => 'logo.svg',
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not an absolute URL');

        // When
        $factory->create();
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function theTenantCarriesTheConfiguredAuthenticationClasses(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), Predicates::wired(), [
            'urn:okta:loa:2fa:any' => 'two_factors',
            1 => 'single_factor',
        ]);

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame(['urn:okta:loa:2fa:any', '1'], $tenant->authenticationContextPolicy->names());
        static::assertSame(TwoFactors::NAME, $tenant->authenticationContextPolicy->classes[0]->predicate->name());
    }

    #[Test]
    public function aClassNamedOnAPredicateNothingWiredCarriesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), Predicates::wired(), [
            '1' => 'attested',
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This provider defines no authentication predicate "attested"; it defines phishing_resistant_hardware, phishing_resistant, two_factors, single_factor.');

        // When
        $factory->create();
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    public function aClaimIsOpenedUnderTheNameTheSpecificationDefines(): void
    {
        // Given
        $factory = new TenantFactory(
            'https://op.test',
            'main',
            null,
            new MockClock(Fixtures::now()),
            Predicates::wired(),
            selfServedClaims: ['nickname', 'profile'],
            claims: self::claims(),
        );

        // When
        $claims = $factory->create()->selfServedClaims;

        // Then
        static::assertTrue($claims->opens('nickname'));
        static::assertTrue($claims->opens('profile'));
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    public function aClaimNamedBySomethingNoWiredClaimAnswersRefusesTheStart(): void
    {
        // Given
        $factory = new TenantFactory(
            'https://op.test',
            'main',
            null,
            new MockClock(Fixtures::now()),
            Predicates::wired(),
            selfServedClaims: ['profile_url'],
            claims: self::claims(),
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This provider holds no claim "profile_url" a person could change of themselves; it holds nickname, profile, picture, website.');

        // When
        $factory->create();
    }

    #[Test]
    public function aPolicyTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'main', null, new MockClock(Fixtures::now()), Predicates::wired(), [
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
     * RFC 9562 §5.5
     */
    #[Test]
    public function theIdentifierIsStableAcrossProcessesAndIssuers(): void
    {
        // Given
        $clock = new MockClock(Fixtures::now());

        // When
        $tenant = new TenantFactory('https://op.test', 'main', 'Main tenant', $clock, Predicates::wired())->create();
        $again = new TenantFactory('https://other.test', 'main', null, $clock, Predicates::wired())->create();

        // Then
        static::assertTrue($tenant->id->equals(TenantFactory::identifier('main')));
        static::assertTrue($tenant->equals($again));
        static::assertFalse($tenant->id->equals(TenantFactory::identifier('other')));
    }

    #[Test]
    public function theNameDefaultsToTheHostOfTheIssuer(): void
    {
        // Given
        $factory = new TenantFactory('https://other.test', 'main', null, new MockClock(), Predicates::wired());

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame('other.test', $tenant->name);
    }

    #[Test]
    public function anIssuerTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test/', 'main', null, new MockClock(), Predicates::wired());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $factory->create();
    }

    /**
     * RFC 8414 §3
     */
    #[Test]
    public function anIssuerThatCarriesAPathRefusesTheStart(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test/idp', 'main', null, new MockClock(), Predicates::wired());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The issuer "https://op.test/idp" carries a path: the issuer of a tenant is an origin, the routes of the provider being served at its root.');

        // When
        $factory->create();
    }

    #[Test]
    public function aSlugTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'Not A Slug', null, new MockClock(), Predicates::wired());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $factory->create();
    }

    private static function claims(): WiredClaims
    {
        return new WiredClaims([new Nickname(), new ProfileUrl(), new PictureUrl(), new WebsiteUrl()]);
    }
}
