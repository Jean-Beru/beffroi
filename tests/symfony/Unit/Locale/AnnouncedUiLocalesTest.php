<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Locale;

use App\Locale\AnnouncedUiLocales;
use App\Locale\ServedLocales;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OpenID Connect Discovery 1.0 §3 "ui_locales_supported", RFC 5646 §2.1
 */
final class AnnouncedUiLocalesTest extends TestCase
{
    #[Test]
    public function theLocalesServedAreAnnouncedAsLanguageTagsTheDefaultFirst(): void
    {
        // Given
        $announced = new AnnouncedUiLocales(new ServedLocales(['en', 'fr_CA', 'zh_Hant'], 'fr'));

        // When
        $metadata = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['ui_locales_supported' => ['fr', 'en', 'fr-CA', 'zh-Hant']], $metadata);
    }
}
