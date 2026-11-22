<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Otphp;

use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Totps;
use function intdiv;
use const PHP_INT_MAX;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6238
 */
final class OtphpTotpAlgorithmTest extends TestCase
{
    /**
     * RFC 6238 Appendix B, the SHA-1 rows on six digits
     */
    #[Test]
    #[DataProvider('provideTestVectors')]
    public function itComputesTheCodesOfTheReferenceVectors(int $unixTime, string $code): void
    {
        // When / Then
        static::assertSame($code, Totps::algorithm()->codeAt(Totps::secret(), intdiv($unixTime, TotpCredential::PERIOD)));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideTestVectors(): iterable
    {
        yield '1970-01-01T00:00:59Z' => [59, '287082'];
        yield '2005-03-18T01:58:29Z' => [1_111_111_109, '081804'];
        yield '2005-03-18T01:58:31Z' => [1_111_111_111, '050471'];
        yield '2009-02-13T23:31:30Z' => [1_234_567_890, '005924'];
        yield '2033-05-18T03:33:20Z' => [2_000_000_000, '279037'];
        yield '2603-10-11T11:33:20Z' => [20_000_000_000, '353130'];
    }

    #[Test]
    public function theProvisioningUriNamesTheIssuerTheAccountAndTheSecret(): void
    {
        // When
        $uri = Totps::algorithm()->provisioningUri(Totps::secret(), 'Acme', 'alice');

        // Then
        static::assertSame('otpauth://totp/Acme%3Aalice?issuer=Acme&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $uri);
    }

    #[Test]
    public function aColonInTheIssuerOrTheAccountIsShownAsASpace(): void
    {
        // When
        $uri = Totps::algorithm()->provisioningUri(Totps::secret(), 'Acme:Corp', 'alice:admin');

        // Then
        static::assertStringStartsWith('otpauth://totp/Acme%20Corp%3Aalice%20admin?issuer=Acme%20Corp&', $uri);
    }

    #[Test]
    #[DataProvider('provideStepsOutOfRange')]
    public function aStepOutOfWhatAUnixTimeCountsIsRefused(int $step): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A time step is never negative (RFC 6238 §4.2), nor beyond what a Unix time counts.');

        // When
        Totps::algorithm()->codeAt(Totps::secret(), $step);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideStepsOutOfRange(): iterable
    {
        yield 'negative' => [-1];
        yield 'beyond the last Unix time' => [intdiv(PHP_INT_MAX, TotpCredential::PERIOD) + 1];
    }

    #[Test]
    #[DataProvider('provideEmptyLabelParts')]
    public function anEmptyIssuerOrAccountIsRefused(string $issuer, string $account, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        Totps::algorithm()->provisioningUri(Totps::secret(), $issuer, $account);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideEmptyLabelParts(): iterable
    {
        yield 'no issuer' => ['', 'alice', 'The issuer of a provisioning URI is not empty.'];
        yield 'no account' => ['Acme', '', 'The account of a provisioning URI is not empty.'];
    }
}
