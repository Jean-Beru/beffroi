<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\KeyManagement;

use Beffroi\Core\Bridge\KeyManagement\KmsKeyId;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.1: "{tenant}" in the KMS key identifier stands for the slug of the tenant.
 */
final class KmsKeyIdTest extends TestCase
{
    #[Test]
    public function thePlaceholderIsTheSlugOfTheTenant(): void
    {
        // When / Then
        static::assertSame('beffroi-acme', new KmsKeyId('beffroi-{tenant}')->of(Fixtures::tenant()));
    }

    #[Test]
    public function anIdentifierWithoutThePlaceholderIsTheSameForEveryTenant(): void
    {
        // When / Then
        static::assertSame('signing', new KmsKeyId('signing')->of(Fixtures::tenant('globex', 'https://id.globex.example')));
    }

    /**
     * The same identifier from the slug alone, for the caller that has no tenant to hand over: a data key
     * store is built for the tenant a scope names, and a scope carries a slug and not a row
     * (decision 0018).
     */
    #[Test]
    public function theSlugAloneResolvesTheSameIdentifier(): void
    {
        // Given
        $pattern = new KmsKeyId('beffroi-{tenant}');

        // When / Then
        static::assertSame($pattern->of(Fixtures::tenant('globex', 'https://id.globex.example')), $pattern->forSlug('globex'));
    }
}
