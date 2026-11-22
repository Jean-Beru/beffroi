<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_diff;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use function method_exists;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use ReflectionNamedType;
use ReflectionProperty;
use function sort;
use function str_starts_with;

/**
 * Decision 0027
 */
final class OneEmbeddableRemainsTest extends DatabaseTestCase
{
    private const int FIELDS = 17;

    private const int TYPES = 8;

    private const int TYPES_THAT_READ_A_REGISTRY = 2;

    private const string PACKAGES = 'Beffroi\\';

    private const string TYPE_PREFIX = 'beffroi_';

    #[Test]
    public function theMappingsOfTheProviderEmbedOneObject(): void
    {
        // When / Then
        static::assertSame([AuthorizationRequest::class], array_keys(self::embeddedObjects()));
    }

    #[Test]
    public function oneEntityEmbedsThatObject(): void
    {
        // When / Then
        static::assertSame([Interaction::class], self::embeddedObjects()[AuthorizationRequest::class]);
    }

    #[Test]
    public function theClientOfARequestIsTheOnePropertyNoFieldCarries(): void
    {
        // Given
        $properties = array_map(
            static fn (ReflectionProperty $property): string => $property->getName(),
            new ReflectionClass(AuthorizationRequest::class)->getProperties(),
        );
        $type = new ReflectionProperty(AuthorizationRequest::class, 'client')->getType();

        // When
        $carriedByNoField = array_values(array_diff($properties, array_keys(self::fields())));

        // Then
        static::assertSame(['client'], $carriedByNoField);
        static::assertSame(Client::class, $type instanceof ReflectionNamedType ? $type->getName() : null);
        static::assertArrayNotHasKey(Client::class, self::mappedClasses());
    }

    #[Test]
    public function theEntityThatEmbedsItHoldsItsClientOnIt(): void
    {
        // Given
        $client = self::client();
        $request = new AuthorizationRequest($client, $client->registration->redirectUris[0], new Scopes([new Scope('openid')]), null);
        $interaction = new Interaction(Secrets::draw(), self::tenant(), $request, null, self::now(), self::now()->modify('+10 minutes'));

        // When / Then
        static::assertSame($request, $interaction->clientHolder());
    }

    #[Test]
    public function theSeventeenFieldsOfTheRequestAreColumnsOfTheInteraction(): void
    {
        // When / Then
        static::assertCount(self::FIELDS, self::fields());
        static::assertSame('beffroi_interaction', self::entityManager()->getClassMetadata(Interaction::class)->getTableName());
    }

    /**
     * Decision 0027
     */
    #[Test]
    public function aSingleColumnWouldHaveToAbsorbEightTypesOfTheProvider(): void
    {
        // When / Then
        static::assertCount(self::TYPES, self::typesOfTheProvider());
    }

    #[Test]
    public function twoOfThoseTypesAreHandedARegistryAtBoot(): void
    {
        // Given
        $handed = [];
        foreach (self::typesOfTheProvider() as $name) {
            if (method_exists(self::typesOfTheConnection()->get($name), 'resolveWith')) {
                $handed[] = $name;
            }
        }

        // When / Then
        static::assertCount(self::TYPES_THAT_READ_A_REGISTRY, $handed);
    }

    /**
     * @return array<class-string, list<class-string>> the entities that embed each object
     */
    private static function embeddedObjects(): array
    {
        $embedded = [];
        foreach (self::entityManager()->getMetadataFactory()->getAllMetadata() as $metadata) {
            if ($metadata->isEmbeddedClass || $metadata->isMappedSuperclass || ! str_starts_with($metadata->getName(), self::PACKAGES)) {
                continue;
            }
            foreach ($metadata->embeddedClasses as $mapping) {
                $embedded[$mapping->class][] = $metadata->getName();
            }
        }

        return $embedded;
    }

    /**
     * @return array<string, string> each field of the request, by its column
     */
    private static function fields(): array
    {
        $metadata = self::entityManager()->getClassMetadata(Interaction::class);
        $fields = [];
        foreach ($metadata->fieldMappings as $field => $mapping) {
            if ($mapping->originalClass !== AuthorizationRequest::class) {
                continue;
            }
            $fields[$mapping->originalField ?? $field] = $metadata->getColumnName($field);
        }

        return $fields;
    }

    /**
     * @return list<string>
     */
    private static function typesOfTheProvider(): array
    {
        $types = [];
        foreach (self::entityManager()->getClassMetadata(Interaction::class)->fieldMappings as $mapping) {
            if ($mapping->originalClass !== AuthorizationRequest::class || ! str_starts_with($mapping->type, self::TYPE_PREFIX)) {
                continue;
            }
            $types[] = $mapping->type;
        }
        $types = array_values(array_unique($types));
        sort($types);

        return $types;
    }

    /**
     * @return array<class-string, true>
     */
    private static function mappedClasses(): array
    {
        $classes = [];
        foreach (self::entityManager()->getMetadataFactory()->getAllMetadata() as $metadata) {
            $classes[$metadata->getName()] = true;
        }

        return $classes;
    }
}
