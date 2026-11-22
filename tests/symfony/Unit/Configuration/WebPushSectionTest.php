<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\WebPushSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Architecture §5.6, Decision 0030
 */
final class WebPushSectionTest extends TestCase
{
    #[Test]
    #[DataProvider('provideSubjects')]
    public function webPushIsOnWhileASubjectIsNamed(?string $subject, bool $on): void
    {
        // When / Then
        static::assertSame($on, WebPushSection::role($subject)->on);
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function provideSubjects(): iterable
    {
        yield 'none' => [null, false];
        yield 'an address' => ['mailto:operator@op.test', true];
        yield 'a page' => ['https://op.test/contact', true];
    }

    /**
     * RFC 8292 §2.1
     */
    #[Test]
    public function anEmptySubjectIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "web_push.subject" names the "mailto:" or "https:" URI a push service can reach the operator at (RFC 8292 section 2.1), and it is empty.');

        // When
        WebPushSection::role('');
    }
}
