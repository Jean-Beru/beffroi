<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

final class BundleBootTest extends KernelTestCase
{
    #[Test]
    public function theBundleBootsAndExposesItsExtension(): void
    {
        $bundles = self::bootKernel()->getBundles();

        static::assertArrayHasKey('HeidiBundle', $bundles);
        static::assertSame('heidi', $bundles['HeidiBundle']->getContainerExtension()?->getAlias());
    }

    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }
}
