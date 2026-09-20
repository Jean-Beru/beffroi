<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\KeyManagement;

use Heidi\Core\Bridge\KeyManagement\KmsKeyId;
use Heidi\Core\Tests\Fixture\Fixtures;
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
        static::assertSame('heidi-acme', new KmsKeyId('heidi-{tenant}')->of(Fixtures::tenant()));
    }

    #[Test]
    public function anIdentifierWithoutThePlaceholderIsTheSameForEveryTenant(): void
    {
        // When / Then
        static::assertSame('signing', new KmsKeyId('signing')->of(Fixtures::tenant('globex', 'https://id.globex.example')));
    }
}
