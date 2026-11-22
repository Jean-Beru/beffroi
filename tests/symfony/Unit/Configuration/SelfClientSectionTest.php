<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\DependencyInjection\BeffroiExtension;
use App\Configuration\SelfClientSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

final class SelfClientSectionTest extends TestCase
{
    private const string SECRET = '%env(APP_OIDC_SECRET)%';

    /**
     * OIDC Core §3.1.2.1, RFC 6749 §2.3.1
     */
    #[Test]
    public function theFirewallOfTheApplicationNamesWhatItWasDeclaredWith(): void
    {
        // When
        $parameters = new SelfClientSection()->parameters([self::declared()]);

        // Then
        static::assertSame(
            [
                SelfClientSection::ISSUER => 'https://op.example',
                SelfClientSection::CLIENT_ID => 'app',
                SelfClientSection::SECRET => self::SECRET,
            ],
            $parameters,
        );
    }

    #[Test]
    public function aValueALaterFileWritesIsTheOneExposed(): void
    {
        // Given
        $later = [
            'self_client' => [
                'client_id' => 'portal',
            ],
        ];

        // When
        $parameters = new SelfClientSection()->parameters([self::declared(), $later]);

        // Then
        static::assertSame('portal', $parameters[SelfClientSection::CLIENT_ID] ?? null);
    }

    #[Test]
    public function anApplicationThatDeclaresNoClientExposesNothing(): void
    {
        // Given
        $configs = [
            [
                'tenant' => [
                    'issuer' => 'https://op.example',
                ],
            ],
        ];

        // When / Then
        static::assertSame([], new SelfClientSection()->parameters($configs));
    }

    /**
     * Decision 0006
     */
    #[Test]
    #[DataProvider('provideSecretsWrittenInTheFile')]
    public function aSecretWrittenInTheFileIsRefused(string $secret): void
    {
        // Given
        $configs = [self::declared($secret)];

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "self_client.secret" is one environment variable, "%env(NAME)%": the secret of the application reaches its firewall as the parameter "beffroi.self_client.secret", which names the variable and never holds the secret.');

        // When
        new SelfClientSection()->parameters($configs);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSecretsWrittenInTheFile(): iterable
    {
        yield 'the secret itself' => ['a-secret-of-the-application-of-at-least-32-characters'];
        yield 'a parameter' => ['%app.oidc_secret%'];
        yield 'a variable among other text' => ['%env(APP_OIDC_SECRET)%-and-more'];
        yield 'two variables' => ['%env(APP_OIDC_SECRET)%%env(APP_OIDC_PEPPER)%'];
    }

    #[Test]
    #[DataProvider('provideSecretsReadFromTheEnvironment')]
    public function aSecretReadFromTheEnvironmentIsExposedAsItIsWritten(string $secret): void
    {
        // When
        $parameters = new SelfClientSection()->parameters([self::declared($secret)]);

        // Then
        static::assertSame($secret, $parameters[SelfClientSection::SECRET] ?? null);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSecretsReadFromTheEnvironment(): iterable
    {
        yield 'a variable' => ['%env(APP_OIDC_SECRET)%'];
        yield 'a file a variable names' => ['%env(file:APP_OIDC_SECRET_FILE)%'];
        yield 'two processors' => ['%env(trim:file:APP_OIDC_SECRET_FILE)%'];
    }

    #[Test]
    public function theProviderExposesThemBeforeAnyExtensionIsLoaded(): void
    {
        // Given
        $builder = new ContainerBuilder();
        $builder->registerExtension(new BeffroiExtension());
        $builder->loadFromExtension('beffroi', self::declared());
        $instanceof = [];

        // When
        new BeffroiExtension()->prependExtension(
            new ContainerConfigurator($builder, new PhpFileLoader($builder, new FileLocator()), $instanceof, '', ''),
            $builder,
        );

        // Then
        static::assertSame(self::SECRET, $builder->getParameterBag()->all()[SelfClientSection::SECRET] ?? null);
    }

    /**
     * @return array<string, mixed>
     */
    private static function declared(string $secret = self::SECRET): array
    {
        return [
            'tenant' => [
                'issuer' => 'https://op.example',
            ],
            'self_client' => [
                'redirect_route' => 'app_oidc_callback',
                'secret' => $secret,
            ],
        ];
    }
}
