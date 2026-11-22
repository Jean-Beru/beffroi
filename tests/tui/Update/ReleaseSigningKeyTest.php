<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Update\GpgvSignature;
use function file_get_contents;
use function is_int;
use function ord;
use function pack;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sha1;
use function strlen;
use function strtoupper;
use function substr;
use function unpack;

/**
 * The keyring the program carries holds the key the releases are signed with, and no other.
 */
final class ReleaseSigningKeyTest extends TestCase
{
    /**
     * RFC 9580 §4.2 (packet headers), §5.5.4 (the fingerprint of a version 4 key).
     */
    #[Test]
    public function theKeyringHoldsThePinnedPrimaryKeyAlone(): void
    {
        // Given
        $keyring = (string) file_get_contents(__DIR__ . '/../../../apps/tui/resources/' . GpgvSignature::RELEASES_KEYRING);

        // When
        $keys = [];
        foreach (self::packets($keyring) as [$tag, $body]) {
            if ($tag === 6 || $tag === 14) {
                $keys[] = [$tag, strtoupper(sha1("\x99" . pack('n', strlen($body)) . $body))];
            }
        }

        // Then
        static::assertSame([[6, GpgvSignature::RELEASES]], $keys);
    }

    /**
     * @return list<array{int, string}> the tag and the body of each packet
     */
    private static function packets(string $keyring): array
    {
        $packets = [];
        $offset = 0;
        while ($offset < strlen($keyring)) {
            $header = ord($keyring[$offset]);
            if (($header & 0x40) !== 0) {
                $tag = $header & 0x3F;
                $first = ord($keyring[$offset + 1]);
                [$length, $size] = match (true) {
                    $first < 192 => [$first, 2],
                    $first < 224 => [(($first - 192) << 8) + ord($keyring[$offset + 2]) + 192, 3],
                    default => [self::number(substr($keyring, $offset + 2, 4), 'N'), 6],
                };
            } else {
                $tag = ($header >> 2) & 0x0F;
                [$length, $size] = match ($header & 0x03) {
                    0 => [ord($keyring[$offset + 1]), 2],
                    1 => [self::number(substr($keyring, $offset + 1, 2), 'n'), 3],
                    default => [self::number(substr($keyring, $offset + 1, 4), 'N'), 5],
                };
            }
            $packets[] = [$tag, substr($keyring, $offset + $size, $length)];
            $offset += $size + $length;
        }

        return $packets;
    }

    private static function number(string $octets, string $format): int
    {
        $number = unpack($format, $octets)[1] ?? null;

        return is_int($number) ? $number : static::fail('The keyring ends inside a packet header.');
    }
}
