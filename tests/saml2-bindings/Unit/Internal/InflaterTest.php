<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Internal\Inflater;
use Beffroi\Saml2\Bindings\Tests\Support\DeflateBomb;
use function deflate_add;
use function deflate_init;
use function gzcompress;
use function gzencode;
use function intdiv;
use LogicException;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function strlen;
use function substr;
use const ZLIB_ENCODING_RAW;
use const ZLIB_FINISH;
use const ZLIB_FIXED;
use const ZLIB_FULL_FLUSH;
use const ZLIB_SYNC_FLUSH;

/**
 * B-7, B-8, section 6.1 step 8, RFC 1951, SAML Bindings §3.4.4.1 step 2
 */
final class InflaterTest extends TestCase
{
    use CodecFixtures;

    private const string MESSAGE = 'behaviour/authn-request-unsigned.xml';

    /**
     * B-8, RFC 1951
     */
    #[Test]
    #[DataProvider('provideRawStreams')]
    public function itInflatesARawDeflateStream(string $deflated): void
    {
        // When
        $inflated = Inflater::inflate($deflated, 65_536);

        // Then
        static::assertSame(self::fixture(self::MESSAGE), $inflated);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRawStreams(): iterable
    {
        $message = self::fixture(self::MESSAGE);

        yield 'the default level, as SimpleSAMLphp writes it' => [self::deflated($message)];
        yield 'level 9' => [self::deflated($message, ['level' => 9])];
        yield 'level 0, stored blocks' => [self::deflated($message, ['level' => 0])];
        yield 'fixed Huffman codes' => [self::deflated($message, ['strategy' => ZLIB_FIXED])];
        yield 'two blocks' => [self::inTwoBlocks($message)];
    }

    /**
     * B-8, RFC 1951 §3.2.3
     */
    #[Test]
    public function itInflatesAnEmptyStream(): void
    {
        // When
        $inflated = Inflater::inflate(self::deflated(''), 65_536);

        // Then
        static::assertSame('', $inflated);
    }

    /**
     * B-7, section 7
     */
    #[Test]
    public function itAcceptsAMessageOfExactlyTheBound(): void
    {
        // Given
        $message = self::fixture(self::MESSAGE);

        // When
        $inflated = Inflater::inflate(self::deflated($message), strlen($message));

        // Then
        static::assertSame($message, $inflated);
    }

    /**
     * §9.2 row 22, B-7, B-11
     */
    #[Test]
    public function itRefusesAMessageOneByteOverTheBound(): void
    {
        // Given
        $message = self::fixture(self::MESSAGE);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 507 bytes (B-7).');

        // When
        Inflater::inflate(self::deflated($message), strlen($message) - 1);
    }

    /**
     * §9.2 row 22, B-7
     */
    #[Test]
    public function itRefusesADeflateBomb(): void
    {
        // Given
        $bomb = DeflateBomb::inflatingTo(1024);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 65536 bytes (B-7).');

        // When
        Inflater::inflate($bomb, 65_536);
    }

    /**
     * §9.2 row 22, B-7, section 6.1 step 8
     */
    #[Test]
    public function itRefusesTheOutputWhileInflationRuns(): void
    {
        // Given
        $bomb = substr(DeflateBomb::inflatingTo(1024), 0, -2) . "\x07";

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 65536 bytes (B-7).');

        // When
        Inflater::inflate($bomb, 65_536);
    }

    /**
     * §9.2 row 22, B-7, section 6.1 step 8
     */
    #[Test]
    #[DataProvider('provideBounds')]
    public function itHoldsABombWithinTheBoundPlusOneStep(int $bound): void
    {
        // Given
        $bomb = DeflateBomb::inflatingTo(1024);
        $this->inflateAndForget($bomb, 1);
        $before = memory_get_usage();
        memory_reset_peak_usage();

        // When
        $this->inflateAndForget($bomb, $bound);

        // Then
        static::assertLessThan($bound + 1_032 + 65_536, memory_get_peak_usage() - $before);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideBounds(): iterable
    {
        yield '1 KiB' => [1_024];
        yield 'the default, 64 KiB' => [65_536];
        yield 'the ceiling, 1 MiB' => [1_048_576];
    }

    /**
     * §9.2 row 24, B-8, B-11, RFC 1950, RFC 1952
     */
    #[Test]
    #[DataProvider('provideStreamsThatAreNotRawDeflate')]
    public function itRefusesWhatIsNotRawDeflate(string $deflated): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('The message is not raw DEFLATE (B-8).');

        // When
        Inflater::inflate($deflated, 65_536);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStreamsThatAreNotRawDeflate(): iterable
    {
        $message = self::fixture(self::MESSAGE);

        yield 'wrapped by zlib, RFC 1950' => [self::wrapped(gzcompress($message))];
        yield 'wrapped by gzip, RFC 1952' => [self::wrapped(gzencode($message))];
        yield 'the message itself, not deflated' => [$message];
        yield 'a block of the reserved type' => ["\x07"];
    }

    /**
     * §9.2 row 24, B-8, RFC 1951 §3.2.3
     */
    #[Test]
    #[DataProvider('provideCutStreams')]
    public function itRefusesAStreamCutBeforeItsFinalBlock(string $deflated): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('The DEFLATE stream ends before its final block (B-8).');

        // When
        Inflater::inflate($deflated, 65_536);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCutStreams(): iterable
    {
        $message = self::fixture(self::MESSAGE);
        $deflated = self::deflated($message);

        yield 'its last byte cut' => [substr($deflated, 0, -1)];
        yield 'cut in the middle' => [substr($deflated, 0, intdiv(strlen($deflated), 2))];
        yield 'a block that is not final, flushed' => [self::deflated($message, [], ZLIB_SYNC_FLUSH)];
        yield 'nothing' => [''];
    }

    /**
     * §9.2 row 24, B-8, RFC 1951 §3.2.3
     */
    #[Test]
    #[DataProvider('provideStreamsFollowedByBytes')]
    public function itRefusesBytesAfterTheFinalBlock(string $deflated): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('Bytes follow the final block of the DEFLATE stream (B-8).');

        // When
        Inflater::inflate($deflated, 65_536);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStreamsFollowedByBytes(): iterable
    {
        $deflated = self::deflated(self::fixture(self::MESSAGE));

        yield 'a NUL' => [$deflated . "\0"];
        yield 'an empty final block' => [$deflated . self::deflated('')];
        yield 'the stream a second time' => [$deflated . $deflated];
    }

    /**
     * B-8
     */
    #[Test]
    public function itLetsNoWarningOfZlibReachTheCaller(): void
    {
        // Given
        $reported = [];
        set_error_handler(static function (int $level, string $message) use (&$reported): bool {
            $reported[] = $message;

            return true;
        });

        // When
        try {
            Inflater::inflate(self::wrapped(gzencode(self::fixture(self::MESSAGE))), 65_536);
        } catch (MalformedEncoding) {
        } finally {
            restore_error_handler();
        }

        // Then
        static::assertSame([], $reported);
    }

    /**
     * B-8
     */
    #[Test]
    #[DataProvider('provideStreamsAcceptedAndRefused')]
    public function itGivesTheCallerItsErrorHandlerBack(string $deflated): void
    {
        // Given
        $handler = static fn (): bool => true;
        set_error_handler($handler);

        // When
        try {
            Inflater::inflate($deflated, 65_536);
        } catch (MalformedEncoding) {
        }
        $current = set_error_handler(null);
        restore_error_handler();
        restore_error_handler();

        // Then
        static::assertSame($handler, $current);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStreamsAcceptedAndRefused(): iterable
    {
        $message = self::fixture(self::MESSAGE);

        yield 'accepted' => [self::deflated($message)];
        yield 'refused by zlib' => [self::wrapped(gzencode($message))];
    }

    private function inflateAndForget(string $deflated, int $bound): void
    {
        try {
            Inflater::inflate($deflated, $bound);
        } catch (LimitExceeded) {
        }
    }

    /**
     * RFC 1951
     *
     * @param array<string, int> $options
     */
    private static function deflated(string $bytes, array $options = [], int $flush = ZLIB_FINISH): string
    {
        $context = deflate_init(ZLIB_ENCODING_RAW, $options);
        if ($context === false) {
            throw new LogicException('zlib could not start a deflation.');
        }

        return self::wrapped(deflate_add($context, $bytes, $flush));
    }

    private static function inTwoBlocks(string $bytes): string
    {
        $context = deflate_init(ZLIB_ENCODING_RAW);
        if ($context === false) {
            throw new LogicException('zlib could not start a deflation.');
        }

        return (
            self::wrapped(deflate_add($context, substr($bytes, 0, 200), ZLIB_FULL_FLUSH))
            . self::wrapped(deflate_add($context, substr($bytes, 200), ZLIB_FINISH))
        );
    }

    private static function wrapped(string|false $bytes): string
    {
        if ($bytes === false) {
            throw new LogicException('zlib failed on a fixture.');
        }

        return $bytes;
    }
}
