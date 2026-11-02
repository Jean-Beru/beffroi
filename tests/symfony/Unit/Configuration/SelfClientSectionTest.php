<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Configuration;

use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Bundle\Configuration\SelfClientSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

/**
 * Issue #282: the application signs its users in with the values it declared itself with, which its firewall names as
 * container parameters rather than writing them a second time; they are read from what was written under "beffroi"
 * before any extension is loaded, SecurityBundle coming before this bundle in an application.
 */
final class SelfClientSectionTest extends TestCase
{
    private const string SECRET = '%env(APP_OIDC_SECRET)%';

    /**
     * OIDC Core §3.1.2.1, RFC 6749 §2.3.1: the issuer the application signs in at, the identifier it is known by and
     * the secret it authenticates with.
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

    /**
     * The files are read as the tree reads them, the last that writes a value winning: what the firewall names is
     * what the client was declared with, in every environment.
     */
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
     * Decision 0006: the secret is read from the environment, so that the parameter the firewall names carries the
     * name of a variable and never the secret, and no file of the application holds it.
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

    /**
     * What a processor of the environment reads is still the environment: the variable is exposed as it is written.
     */
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

    /**
     * The bundle sets them before any extension is loaded, which is when the firewall of an application resolves what
     * it names.
     */
    #[Test]
    public function theBundleExposesThemBeforeAnyExtensionIsLoaded(): void
    {
        // Given
        $builder = new ContainerBuilder();
        $builder->registerExtension(new BeffroiBundle()->getContainerExtension() ?? static::fail('The bundle has no extension.'));
        $builder->loadFromExtension('beffroi', self::declared());
        $instanceof = [];

        // When
        new BeffroiBundle()->prependExtension(
            new ContainerConfigurator($builder, new PhpFileLoader($builder, new FileLocator()), $instanceof, '', ''),
            $builder,
        );

        // Then
        static::assertSame(self::SECRET, $builder->getParameterBag()->all()[SelfClientSection::SECRET] ?? null);
    }

    /**
     * What an application writes under "beffroi" when it declares itself, nothing else of the tenant than its issuer.
     *
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
