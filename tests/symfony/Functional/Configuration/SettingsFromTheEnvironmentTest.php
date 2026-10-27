<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Configuration;

use Beffroi\Bundle\Configuration\TokensSection;
use Beffroi\Bundle\Dpop\CachedDpopNonce;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Oidc\Bridge\Null\NoDpopNonce;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Issue #911: what a deployment chooses is an environment variable, and a variable is a value only once the
 * container runs. The kernel of these tests reads four settings the way the application does
 * (config_test.yml), so each test names its value before it boots one, as a deployment names it before it
 * starts: the bounds and the rules of the tree hold it all the same, and a requirement it switches on is
 * the class the provider is wired with.
 */
final class SettingsFromTheEnvironmentTest extends KernelTestCase
{
    private const array VARIABLES = [
        'BEFFROI_TEST_AUTHORIZATION_CODE_TTL',
        'BEFFROI_TEST_REFRESH_TOKEN_TTL',
        'BEFFROI_TEST_STAGING_DELAY',
        'BEFFROI_TEST_DPOP_NONCE_REQUIRED',
    ];

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    /**
     * RFC 6749 §4.1.2, the recommendation the tree makes a bound: a number the environment carries past it
     * stops the issuer of the codes from being built, as the same number written in the file stops the build
     * of the container.
     */
    #[Test]
    public function aLifetimeTheEnvironmentCarriesPastItsBoundIsRefused(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_AUTHORIZATION_CODE_TTL'] = (string) (TokensSection::MAX_AUTHORIZATION_CODE_TTL + 1);
        self::bootKernel();

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "authorization_code_ttl" is a number of seconds from 1 to 600, 601 given.');

        // When
        static::getContainer()->get('test.beffroi.authorization_code_issuer');
    }

    /**
     * Architecture §4.6: no rotation carries a refresh token past the absolute lifetime of its family, ninety
     * days by default.
     */
    #[Test]
    public function aSlidingRefreshLifetimeTheEnvironmentCarriesBeyondTheAbsoluteOneIsRefused(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_REFRESH_TOKEN_TTL'] = '7776001';
        self::bootKernel();

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The sliding lifetime of a refresh token (refresh_token_ttl) cannot exceed the absolute lifetime of its family (refresh_token_absolute_ttl).');

        // When
        static::getContainer()->get('test.beffroi.token_issuer');
    }

    /**
     * Architecture §3.3: a variable left empty is no delay configured, so the delay follows the max-age of the
     * JWK Set, 120 s in this kernel, plus the refetch cooldown of oidc_login.
     */
    #[Test]
    #[DataProvider('provideStagingDelays')]
    public function theStagingDelayOfTheJoseKeysIsTheOneTheEnvironmentNames(string $variable, int $seconds): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_STAGING_DELAY'] = $variable;
        self::bootKernel();

        // When
        $schedule = static::getContainer()->get('test.beffroi.rotation_schedule');

        // Then
        static::assertInstanceOf(RotationSchedule::class, $schedule);
        static::assertSame($seconds, $schedule->stagingDelay->s);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideStagingDelays(): iterable
    {
        yield 'nothing' => ['', 180];
        yield 'a week' => ['604800', 604800];
    }

    /**
     * RFC 9449 §8: the requirement is read once, when the port is built, and is the class it is built as.
     *
     * @param class-string $wired
     */
    #[Test]
    #[DataProvider('provideNonceRequirements')]
    public function theNonceADpopProofIsAskedForIsTheOneTheEnvironmentRequires(string $variable, string $wired): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_DPOP_NONCE_REQUIRED'] = $variable;
        self::bootKernel();

        // When
        $nonce = static::getContainer()->get('test.beffroi.dpop_nonce');

        // Then
        static::assertInstanceOf($wired, $nonce);
    }

    /**
     * @return iterable<string, array{string, class-string}>
     */
    public static function provideNonceRequirements(): iterable
    {
        yield 'required' => ['true', CachedDpopNonce::class];
        yield 'not required' => ['false', NoDpopNonce::class];
    }
}
