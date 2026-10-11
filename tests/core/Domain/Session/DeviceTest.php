<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\DeviceType;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.5: what the user agent of a request says of where it came from, for the pages that
 * show a person where they signed in.
 */
final class DeviceTest extends TestCase
{
    /**
     * Every browser built on Chromium says "Chrome" of itself, and a telephone on Android says "Linux":
     * what is recognised is the most particular needle and never the first that matches anything.
     */
    #[Test]
    #[DataProvider('provideAgentsAndWhatTheySay')]
    public function itNamesTheBrowserAndTheSystemAnAgentSays(string $userAgent, ?string $browser, ?string $platform, DeviceType $type): void
    {
        // When
        $device = Device::readFrom($userAgent);

        // Then
        static::assertNotNull($device);
        static::assertSame($browser, $device->browser);
        static::assertSame($platform, $device->platform);
        static::assertSame($type, $device->type);
    }

    /**
     * @return iterable<string, array{string, string|null, string|null, DeviceType}>
     */
    public static function provideAgentsAndWhatTheySay(): iterable
    {
        yield 'Chrome on Windows' => [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36',
            'Chrome',
            'Windows',
            DeviceType::Desktop,
        ];
        yield 'Edge, which says Chrome of itself too' => [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0',
            'Edge',
            'Windows',
            DeviceType::Desktop,
        ];
        yield 'Firefox on Linux' => [
            'Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0',
            'Firefox',
            'Linux',
            DeviceType::Desktop,
        ];
        yield 'Safari on macOS' => [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15',
            'Safari',
            'macOS',
            DeviceType::Desktop,
        ];
        yield 'Chrome on a telephone, which says Linux of itself' => [
            'Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36',
            'Chrome',
            'Android',
            DeviceType::Mobile,
        ];
        yield 'Safari on an iPhone, which says Mac OS X of itself' => [
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1',
            'Safari',
            'iOS',
            DeviceType::Mobile,
        ];
        yield 'a program that names itself and its version' => ['curl/8.18.0', 'curl', null, DeviceType::Unknown];
    }

    /**
     * A reading that invented a name would be one nobody could tell from a true one, so an agent it
     * recognises nothing in is nothing, and the caller shows the string as it stands.
     */
    #[Test]
    #[DataProvider('provideAgentsThatSayNothing')]
    public function anAgentItRecognisesNothingInIsNothing(?string $userAgent): void
    {
        // When / Then
        static::assertNull(Device::readFrom($userAgent));
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideAgentsThatSayNothing(): iterable
    {
        yield 'none sent' => [null];
        yield 'empty' => [''];
        yield 'a name nothing recognises' => ['a browser of its own'];
    }

    /**
     * The document a column holds a device as, which is also what the provenance of a request nests.
     *
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsItAs(Device $device, array $document): void
    {
        // When / Then
        static::assertSame($document, $device->toDocument());
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itComesBackOutOfItsDocument(Device $device, array $document): void
    {
        // When / Then
        static::assertEquals($device, Device::fromDocument($document));
    }

    /**
     * @return iterable<string, array{Device, array<string, mixed>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a device' => [
            new Device(DeviceType::Desktop, 'Firefox', '140.0', 'Linux'),
            [
                'type' => 'desktop',
                'browser' => 'Firefox',
                'browser_version' => '140.0',
                'platform' => 'Linux',
                'platform_version' => null,
            ],
        ];
        yield 'a device nothing was recognised of' => [
            new Device(),
            [
                'type' => 'unknown',
                'browser' => null,
                'browser_version' => null,
                'platform' => null,
                'platform_version' => null,
            ],
        ];
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotADevice')]
    public function aDocumentThatIsNotADeviceIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        Device::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotADevice(): iterable
    {
        yield 'no type' => [
            [
                'browser' => 'Firefox',
            ],
            'A device names its type.',
        ];
        yield 'a type this provider has no kind for' => [
            [
                'type' => 'toaster',
            ],
            'A device names its type.',
        ];
        yield 'a numeric browser' => [
            [
                'type' => 'desktop',
                'browser' => 140,
            ],
            'The member "browser" must be a string or absent.',
        ];
    }
}
