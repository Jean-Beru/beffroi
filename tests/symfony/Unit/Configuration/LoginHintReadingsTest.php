<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use function array_map;
use App\Configuration\LoginHintReadings;
use Beffroi\Oidc\Application\Hint\UserHintInterface;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ServiceLocator;

/**
 * OIDC Core §3.1.2.1, CIBA Core §7.1, Decision 0030
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

    #[Test]
    #[DataProvider('provideReadingsOfTheProvider')]
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
    public static function provideReadingsOfTheProvider(): iterable
    {
        yield 'the subject' => ['sub'];
        yield 'the username' => ['username'];
    }

    #[Test]
    public function aDeploymentThatNamesNoneIsReadByWhatItTagged(): void
    {
        // When
        $readings = iterator_to_array($this->readings('none'));

        // Then
        static::assertSame([$this->tagged], $readings);
    }

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
