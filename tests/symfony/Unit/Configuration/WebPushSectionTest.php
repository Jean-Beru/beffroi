<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Configuration;

use Beffroi\Bundle\Configuration\WebPushSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Architecture §5.6, decision 0030: naming a subject is what turns web push on, a subject the environment may carry and
 * the container reads when it builds what web push changes.
 */
final class WebPushSectionTest extends TestCase
{
    /**
     * @param string|null $subject what the configuration or the environment names
     */
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
     * RFC 8292 §2.1: an empty subject names nobody a push service could reach, which the tree refuses written and the
     * role refuses carried, before anything sends.
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
