<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Device;

use Heidi\Oidc\Domain\Device\DeviceAuthorizationResponse;
use Heidi\Oidc\Domain\Device\UserCode;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8628 §3.2, §3.3.1: what the client is answered, and the complete URI it may show as a link or a QR
 * code, which is the verification URI carrying the code.
 */
final class DeviceAuthorizationResponseTest extends TestCase
{
    #[Test]
    public function itCarriesTheSixMembersOfTheSpecification(): void
    {
        // Given
        $response = new DeviceAuthorizationResponse('the-device-code', UserCode::of('BCDFGHJK'), 'https://op.test/device', 600, 5);

        // When / Then
        static::assertSame(
            [
                'device_code' => 'the-device-code',
                'user_code' => 'BCDF-GHJK',
                'verification_uri' => 'https://op.test/device',
                'verification_uri_complete' => 'https://op.test/device?user_code=BCDF-GHJK',
                'expires_in' => 600,
                'interval' => 5,
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 8628 §3.3.1: a verification URI that already carries a query gains the code beside what it
     * carries, and never a second question mark.
     */
    #[Test]
    public function theCompleteUriIsBuiltOnWhateverTheVerificationUriCarries(): void
    {
        // Given
        $response = new DeviceAuthorizationResponse('the-device-code', UserCode::of('BCDFGHJK'), 'https://op.test/device?tenant=acme', 600, 5);

        // When / Then
        static::assertSame('https://op.test/device?tenant=acme&user_code=BCDF-GHJK', $response->completeVerificationUri());
    }

    /**
     * RFC 8628 §3.2: a lifetime and an interval a client could not act on are refused where they are
     * written, not where they are read.
     */
    #[Test]
    #[DataProvider('provideNumbersNoClientCouldAct')]
    public function itRefusesALifetimeOrAnIntervalNoClientCouldAct(int $expiresIn, int $interval, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new DeviceAuthorizationResponse('the-device-code', UserCode::of('BCDFGHJK'), 'https://op.test/device', $expiresIn, $interval);
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function provideNumbersNoClientCouldAct(): iterable
    {
        yield 'a code that is already dead' => [0, 5, 'the seconds it still lives, at least one'];
        yield 'a lifetime in the past' => [-1, 5, 'the seconds it still lives, at least one'];
        yield 'no interval at all' => [600, 0, 'a polling interval of at least one second'];
    }
}
