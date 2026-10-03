<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Bundle\Configuration\TenantSection;
use Beffroi\Bundle\Doctrine\TenantNotSynchronizedException;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Doctrine\TenantSynchronizer;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Architecture §5.3: the tenant the services receive is the row, checked against the configuration; the
 * synchroniser writes the row from the configuration, once, and refuses to move an issuer.
 */
final class TenantProviderTest extends DatabaseTestCase
{
    #[Test]
    public function theTenantIsTheRowOfTheConfiguration(): void
    {
        // When
        $tenant = self::tenant();

        // Then
        static::assertTrue($tenant->id->equals(TenantFactory::identifier('default')));
        static::assertSame('https://op.test', (string) $tenant->issuer);
        static::assertSame('op.test', $tenant->name);
        static::assertTrue(self::entityManager()->contains($tenant));
        static::assertSame($tenant, self::entityManager()->find(Tenant::class, $tenant->id));
    }

    /**
     * An entity is not a service: the instance lives as long as the unit of work. Between two requests
     * or two messages the kernel resets its services, Doctrine's registry among them, and the next
     * request gets the tenant of its own unit of work; a cleared entity manager forgets it as well.
     */
    #[Test]
    public function theInstanceIsTheSameWithinAUnitOfWork(): void
    {
        // Given
        $provider = self::service('test.beffroi.tenant_provider', TenantProvider::class);
        $first = $provider->provide();

        // When
        $again = $provider->provide();

        // Then
        static::assertSame($first, $again);
    }

    #[Test]
    public function theInstanceIsForgottenWhenTheEntityManagerIsCleared(): void
    {
        // Given
        $provider = self::service('test.beffroi.tenant_provider', TenantProvider::class);
        $first = $provider->provide();
        self::entityManager()->clear();

        // When
        $second = $provider->provide();

        // Then
        static::assertNotSame($first, $second);
        static::assertFalse(self::entityManager()->contains($first));
        static::assertTrue(self::entityManager()->contains($second));
    }

    #[Test]
    public function theInstanceIsForgottenWhenTheServicesAreReset(): void
    {
        // Given
        $provider = self::service('test.beffroi.tenant_provider', TenantProvider::class);
        $first = $provider->provide();
        self::service('services_resetter', ResetInterface::class)->reset();

        // When
        $second = $provider->provide();

        // Then
        static::assertNotSame($first, $second);
        static::assertTrue(self::entityManager()->contains($second));
        static::assertTrue($second->id->equals($first->id));
    }

    #[Test]
    public function synchronisingAgainWritesNothing(): void
    {
        // Given
        $synchronizer = self::service('test.beffroi.tenant_synchronizer', TenantSynchronizer::class);
        $first = $synchronizer->synchronize();

        // When
        $again = $synchronizer->synchronize();

        // Then
        static::assertSame($first, $again);
        static::assertSame($first, self::tenant());
    }

    #[Test]
    public function aMissingRowRefusesToServe(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', null), self::managers());
        self::entityManager()->createQuery('DELETE FROM Beffroi\Core\Domain\Tenant\Tenant t')->execute();

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/has no row yet/');

        // When
        $provider->provide();
    }

    #[Test]
    public function aRowThatDisagreesWithTheConfigurationRefusesToServe(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://other.test', 'default', null), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/stored with the issuer "https:\/\/op.test" and configured with "https:\/\/other.test"/');

        // When
        $provider->provide();
    }

    #[Test]
    public function aRenamedTenantRefusesToServeUntilSynchronised(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', 'Renamed'), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageIsOrContains('stored with the name "op.test" and configured with "Renamed"');

        // When
        $provider->provide();
    }

    #[Test]
    public function synchronisingARenamedTenantWritesTheNewName(): void
    {
        // Given
        $factory = self::factory('https://op.test', 'default', 'Renamed');
        $provider = new TenantProvider($factory, self::managers());

        // When
        $synchronized = new TenantSynchronizer($factory, self::managers())->synchronize();
        self::reload();

        // Then
        static::assertSame('Renamed', $synchronized->name);
        static::assertSame('Renamed', $provider->provide()->name);
    }

    /**
     * The issuer of a tenant does not change: every token issued so far names it. Another issuer is
     * another tenant, under another slug.
     */
    #[Test]
    public function theSynchroniserRefusesToMoveTheIssuer(): void
    {
        // Given
        $synchronizer = new TenantSynchronizer(self::factory('https://moved.test', 'default', null), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/the issuer of a tenant does not change/');

        // When
        $synchronizer->synchronize();
    }

    #[Test]
    public function anotherSlugIsAnotherTenant(): void
    {
        // When
        $other = new TenantSynchronizer(self::factory('https://other.test', 'other', null), self::managers())->synchronize();
        self::reload();

        // Then
        static::assertTrue($other->id->equals(TenantFactory::identifier('other')));
        $stored = self::entityManager()->find(Tenant::class, $other->id) ?? static::fail('The other tenant was not stored.');
        static::assertTrue(new Issuer('https://other.test')->equals($stored->issuer));
        static::assertSame('https://op.test', (string) self::tenant()->issuer);
    }

    /**
     * Decision 0010: the "acr" policy is the tenant's, stored with it; the row must speak what the
     * configuration says before requests are served.
     */
    #[Test]
    public function aTenantWithAnotherPolicyRefusesToServeUntilSynchronised(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', null, self::OKTA_CLASSES), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageIsOrContains('stored with the authentication_classes "phrh phr 2 1" and configured with "urn:okta:loa:2fa:any urn:okta:loa:1fa:any"');

        // When
        $provider->provide();
    }

    #[Test]
    public function synchronisingATenantWithAnotherPolicyWritesIt(): void
    {
        // Given
        $factory = self::factory('https://op.test', 'default', null, self::OKTA_CLASSES);
        $provider = new TenantProvider($factory, self::managers());

        // When
        $synchronized = new TenantSynchronizer($factory, self::managers())->synchronize();
        self::reload();

        // Then
        static::assertSame(['urn:okta:loa:2fa:any', 'urn:okta:loa:1fa:any'], $synchronized->authenticationContextPolicy->names());
        $stored = $provider->provide()->authenticationContextPolicy;
        static::assertSame(['urn:okta:loa:2fa:any', 'urn:okta:loa:1fa:any'], $stored->names());
        static::assertSame(AuthenticationPredicate::TwoFactors, $stored->classes[0]->predicate);
    }

    /**
     * A tenant that configures nothing speaks the default policy of decision 0010, as the row of a
     * deployment written before the column existed does.
     */
    #[Test]
    public function aTenantThatConfiguresNothingSpeaksTheDefaultPolicy(): void
    {
        // When
        $tenant = new TenantProvider(self::factory('https://op.test', 'default', null), self::managers())->provide();

        // Then
        static::assertTrue(AuthenticationContextPolicy::default()->equals($tenant->authenticationContextPolicy));
    }

    /**
     * Issue #449: what the pages show of the tenant is the tenant's too, stored with it, and the row must
     * speak what the configuration declares before requests are served.
     */
    #[Test]
    public function aTenantWithAnotherLookRefusesToServeUntilSynchronised(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', null, look: self::LOOK), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageIsOrContains('stored with the look "none" and configured with "logo https://acme.example/logo.svg, #1b4b8f on #ffffff"');

        // When
        $provider->provide();
    }

    #[Test]
    public function synchronisingATenantWithAnotherLookWritesIt(): void
    {
        // Given
        $factory = self::factory('https://op.test', 'default', null, look: self::LOOK);
        $provider = new TenantProvider($factory, self::managers());

        // When
        $synchronized = new TenantSynchronizer($factory, self::managers())->synchronize();
        self::reload();

        // Then
        static::assertSame('https://acme.example/logo.svg', $synchronized->look->logoUri?->value);
        $stored = $provider->provide()->look;
        static::assertSame('https://acme.example/logo.svg', $stored->logoUri?->value);
        static::assertSame('#1b4b8f', $stored->primaryColor);
        static::assertSame('#ffffff', $stored->primaryContentColor);
    }

    /**
     * A tenant that declares no look has none, as the row of a deployment written before the column
     * existed has none: the column defaults to an empty document.
     */
    #[Test]
    public function aTenantThatDeclaresNoLookHasNone(): void
    {
        // When
        $tenant = new TenantProvider(self::factory('https://op.test', 'default', null), self::managers())->provide();

        // Then
        static::assertFalse($tenant->look->isDeclared());
    }

    private const array LOOK = [
        'logo_uri' => 'https://acme.example/logo.svg',
        'primary_color' => '#1b4b8f',
        'primary_content_color' => '#ffffff',
    ];

    private const array OKTA_CLASSES = [
        'urn:okta:loa:2fa:any' => 'two_factors',
        'urn:okta:loa:1fa:any' => 'single_factor',
    ];

    /**
     * @param array<array-key, string> $authenticationClasses
     * @param array<array-key, mixed> $look
     */
    /**
     * The claims the kernel of these tests opens (config_test.yml), so a factory built here says what the
     * row says and a test about one thing is not a test about that too.
     */
    private const array SELF_SERVED_CLAIMS = ['nickname', 'zoneinfo', 'locale', 'birthdate'];

    /**
     * @param array<array-key, string> $authenticationClasses
     * @param array<array-key, mixed> $look
     * @param array<array-key, mixed> $selfServedClaims
     */
    private static function factory(
        string $issuer,
        string $slug,
        ?string $name,
        array $authenticationClasses = TenantSection::DEFAULT_AUTHENTICATION_CLASSES,
        array $look = [],
        array $selfServedClaims = self::SELF_SERVED_CLAIMS,
    ): TenantFactory {
        return new TenantFactory($issuer, $slug, $name, new MockClock(self::now()), $authenticationClasses, $look, $selfServedClaims);
    }
}
