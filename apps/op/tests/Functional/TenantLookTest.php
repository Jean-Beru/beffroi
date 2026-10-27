<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use PHPUnit\Framework\Attributes\Test;

/**
 * What the tenant shows of itself on a page of this application when its deployment names nothing (issues
 * #449 and #911): the suite reads .env and .env.test and never .env.local, which is what "composer dump-env
 * prod" compiles into an image, plus the fixtures of the suite, none of which names a look.
 */
final class TenantLookTest extends BrowserTestCase
{
    /**
     * The placeholder mark the image serves at the origin of its issuer, under the name of the tenant, which is
     * the host of that issuer while the deployment names none.
     */
    #[Test]
    public function aPageShowsThePlaceholderMarkOfTheImageUnderTheHostOfTheIssuer(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $logo = $this->accountHome()->filter('img[data-tenant="logo"]');

        // Then
        static::assertSame('https://op.test/tenant-logo.svg', $logo->attr('src'));
        static::assertSame('op.test', $logo->attr('alt'));
    }

    #[Test]
    public function aPageIsDrawnInTheColoursOfTheImage(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $style = $this->accountHome()->filter('head style')->text();

        // Then
        static::assertStringContainsString('--color-primary: #1f6feb; --color-primary-content: #ffffff;', $style);
    }
}
