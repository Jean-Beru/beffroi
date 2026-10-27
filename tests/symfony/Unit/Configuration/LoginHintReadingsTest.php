<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Configuration;

use function array_map;
use Beffroi\Bundle\Configuration\LoginHintReadings;
use Beffroi\Oidc\Application\Hint\UserHintInterface;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ServiceLocator;

/**
 * OIDC Core §3.1.2.1, CIBA Core §7.1: a side of the provider reads a "login_hint" the way the deployment names, a name
 * an environment variable may carry, held to the names the tree accepts when the container builds the readings of
 * that side (decision 0030).
 */
final class LoginHintReadingsTest extends TestCase
{
    private UserHintInterface $tagged;

    private UserHintInterface $subject;

    private UserHintInterface $username;

    protected function setUp(): void
    {
        $this->tagged = static::createStub(UserHintInterface::class);
        $this->subject = static::createStub(UserHintInterface::class);
        $this->username = static::createStub(UserHintInterface::class);
    }

    /**
     * The readings a deployment tagged come first, then the one of the bundle the configuration names.
     */
    #[Test]
    #[DataProvider('provideReadingsOfTheBundle')]
    public function theReadingTheConfigurationNamesFollowsThoseTheDeploymentTagged(string $name): void
    {
        // When
        $readings = iterator_to_array($this->readings($name));

        // Then
        static::assertSame([$this->tagged, $this->bundled()[$name]], $readings);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideReadingsOfTheBundle(): iterable
    {
        yield 'the subject' => ['sub'];
        yield 'the username' => ['username'];
    }

    /**
     * A deployment that tags a reading of its own names none of the bundle, so that the parameter is read one way.
     */
    #[Test]
    public function aDeploymentThatNamesNoneIsReadByWhatItTagged(): void
    {
        // When
        $readings = iterator_to_array($this->readings('none'));

        // Then
        static::assertSame([$this->tagged], $readings);
    }

    /**
     * A name an environment variable carries is held to the names of the tree, which refuses any other written.
     */
    #[Test]
    public function aNameNoReadingAnswersToIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "interaction.login_hint" names one of "sub", "username", "none", "email" given.');

        // When
        $this->readings('email');
    }

    private function readings(string $name): LoginHintReadings
    {
        return new LoginHintReadings(
            [$this->tagged],
            $name,
            new ServiceLocator(array_map(
                static fn (UserHintInterface $reading): callable => static fn (): UserHintInterface => $reading,
                $this->bundled(),
            )),
            'interaction.login_hint',
        );
    }

    /**
     * @return array<string, UserHintInterface>
     */
    private function bundled(): array
    {
        return [
            'sub' => $this->subject,
            'username' => $this->username,
        ];
    }
}
