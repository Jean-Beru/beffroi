<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Configuration;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Issue #282: the secret of the application is read from the environment, and its identifier may be, so they are
 * values only once the container runs. The source of its client holds the secret to what any secret of a declared
 * client is held to and to being its own, and the identifier to being nobody else's, when it is built; the kernel of
 * these tests reads both as an application does (config_test.yml), so each test names its value before it boots one.
 */
final class SelfClientFromTheEnvironmentTest extends KernelTestCase
{
    private const string SECRET = 'BEFFROI_TEST_APPLICATION_SECRET';

    private const string CLIENT_ID = 'BEFFROI_TEST_APPLICATION_CLIENT_ID';

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER[self::SECRET], $_ENV[self::SECRET], $_SERVER[self::CLIENT_ID], $_ENV[self::CLIENT_ID]);
    }

    /**
     * RFC 6749 appendix A.2, RFC 6819 §5.1.4.2.2: a secret the environment gives is held to the length any declared
     * secret is held to.
     */
    #[Test]
    public function aSecretTooShortToBeGeneratedRefusesTheSourceOfTheApplication(): void
    {
        // Given
        $_SERVER[self::SECRET] = 'chosen-rather-than-drawn';
        self::bootKernel();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The secret of the client "app" must be at least 32 visible ASCII characters long; generate it, do not choose it.');

        // When
        static::getContainer()->get('test.beffroi.self_client');
    }

    /**
     * The secret of the kernel of these tests is "test" (config_test.yml): a variable that gives it is refused,
     * whatever its name, before its length is even looked at.
     */
    #[Test]
    public function theSecretOfTheKernelRefusesTheSourceOfTheApplication(): void
    {
        // Given
        $_SERVER[self::SECRET] = 'test';
        self::bootKernel();

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "self_client.secret" is the secret of the kernel: the application authenticates with a secret of its own, which its token requests carry over HTTP.');

        // When
        static::getContainer()->get('test.beffroi.self_client');
    }

    /**
     * One identifier is one client of the tenant: an identifier the environment gives is compared with the clients of
     * the file when the source is built, the tree only seeing what the variable stands for.
     */
    #[Test]
    public function theIdentifierOfADeclaredClientRefusesTheSourceOfTheApplication(): void
    {
        // Given
        $_SERVER[self::CLIENT_ID] = 'oidc-demo';
        self::bootKernel();

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "self_client.client_id" names "oidc-demo", a client "clients" declares as well: one identifier is one client of the tenant.');

        // When
        static::getContainer()->get('test.beffroi.self_client');
    }
}
