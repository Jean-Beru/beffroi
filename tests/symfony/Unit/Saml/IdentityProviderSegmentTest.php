<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Saml;

use App\Saml\IdentityProviderSegment;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-65
 */
final class IdentityProviderSegmentTest extends TestCase
{
    /**
     * S-65, RFC 4648 §5
     */
    #[Test]
    public function theSegmentIsTheEntityIdInBase64Url(): void
    {
        // When / Then
        static::assertSame('aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8_aWQ9MQ', IdentityProviderSegment::of('https://idp.example/saml2/?id=1'));
    }

    /**
     * S-65
     */
    #[Test]
    public function theEntityIdIsReadBackFromTheSegment(): void
    {
        // When / Then
        static::assertSame('https://idp.example/saml2/?id=1', IdentityProviderSegment::entityIdOf('aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8_aWQ9MQ'));
    }

    /**
     * S-65, M-6
     */
    #[Test]
    #[DataProvider('provideSegmentsOfNoProvider')]
    public function aSegmentThatIsNoEntityIdNamesNoProvider(string $segment): void
    {
        // When / Then
        static::assertNull(IdentityProviderSegment::entityIdOf($segment));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSegmentsOfNoProvider(): iterable
    {
        yield 'padded' => ['aHR0cHM6Ly9pZHAuZXhhbXBsZQ=='];
        yield 'the standard alphabet' => ['aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8/aWQ9MQ'];
        yield 'other trailing bits' => ['aHR0cHM6Ly9pZHAuZXhhbXBsZS9zYW1sMi8_aWQ9MR'];
        yield 'not absolute' => [IdentityProviderSegment::of('idp.example')];
        yield 'empty' => [''];
    }
}
