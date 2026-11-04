<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Bridge\Model\ModelEntityId;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * spec/saml.md S-38, M-6
 */
final class ModelEntityIdTest extends TestCase
{
    /**
     * S-38, M-6
     */
    #[Test]
    public function anEntityIdOfTheLongestLengthIsRead(): void
    {
        // Given
        $entityId = 'urn:' . str_repeat('a', 1_020);

        // When / Then
        static::assertSame($entityId, ModelEntityId::read($entityId));
    }

    /**
     * S-38, M-6, M-16
     */
    #[Test]
    #[DataProvider('provideEntityIdsRefused')]
    public function anEntityIdThatIsNoUriOfTheModelIsRefused(string $entityId, string $rule): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The entity ID of the service provider of a tenant is refused (spec/saml.md S-38): ' . $rule);

        // When
        ModelEntityId::read($entityId);
    }

    /**
     * S-42, M-6
     */
    #[Test]
    public function theEntityIdOfAnIdentityProviderIsRead(): void
    {
        // When / Then
        static::assertSame(
            'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata',
            ModelEntityId::ofIdentityProvider('https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata'),
        );
    }

    /**
     * S-42, M-6, M-16
     */
    #[Test]
    #[DataProvider('provideEntityIdsRefused')]
    public function anEntityIdOfAnIdentityProviderThatIsNoUriOfTheModelIsRefused(string $entityId, string $rule): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The entity ID of an identity provider is refused (spec/saml.md S-42): ' . $rule);

        // When
        ModelEntityId::ofIdentityProvider($entityId);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEntityIdsRefused(): iterable
    {
        $notAbsolute = 'A URI is not absolute (M-6).';
        $notVisible = 'A URI holds whitespace, a control, format or invisible character, or bytes that are not UTF-8 (M-6).';
        yield 'empty' => ['', $notAbsolute];
        yield 'no scheme' => ['sp.acme.example', $notAbsolute];
        yield 'whitespace' => ['https://id.acme.example/saml sp', $notVisible];
        yield 'a control character' => ["https://id.acme.example/saml\x07sp", $notVisible];
        yield 'a zero-width space, a format character' => ["https://id.acme.example/saml\u{200B}sp", $notVisible];
        yield 'a right-to-left override, a format character' => ["https://id.acme.example/\u{202E}saml", $notVisible];
        yield 'longer than 1024 characters' => ['urn:' . str_repeat('a', 1_021), 'A URI is longer than 1024 characters (M-6).'];
    }
}
