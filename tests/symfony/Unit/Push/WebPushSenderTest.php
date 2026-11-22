<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Push;

use App\Http\Timeout;
use App\Push\WebPushSender;
use Beffroi\Core\Port\ApplicationServerKeyProviderInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpClient\MockHttpClient;

/**
 * RFC 8292 §2.1
 */
final class WebPushSenderTest extends TestCase
{
    #[Test]
    public function itIsNotBuiltWithAnEmptySubject(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "web_push.subject" names the "mailto:" or "https:" URI a push service can reach the operator at (RFC 8292 section 2.1), and it is empty.');

        // When
        new WebPushSender(static::createStub(ApplicationServerKeyProviderInterface::class), new MockHttpClient(), new MockClock(), '', new Timeout(1.0));
    }
}
