<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Configuration;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

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
     * RFC 6749 appendix A.2, RFC 6819 §5.1.4.2.2
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
