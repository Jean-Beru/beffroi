<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Key;

use Heidi\Bundle\Key\KmsClientPass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\KeyManagement\EncrypterInterface;

/**
 * Issue #208: the bundle seals with a KMS client the framework configuration registers, and the pass is
 * what turns a name nothing answers to into a failure an operator can read.
 */
final class KmsClientPassTest extends TestCase
{
    #[Test]
    public function aNameAClientAnswersToPasses(): void
    {
        // Given
        $container = self::container('op');
        $container->register('key_management.op', EncrypterInterface::class)->addTag('key_management.client', [
            'key' => 'op',
        ]);

        // When
        new KmsClientPass()->process($container);

        // Then
        static::assertSame('key_management.op', (string) $container->getAlias('heidi.kms'));
    }

    #[Test]
    public function aNameNoClientAnswersToFailsTheBuildAndNamesTheOnesThatWouldHave(): void
    {
        // Given
        $container = self::container('aws');
        $container->register('key_management.op', EncrypterInterface::class)->addTag('key_management.client', [
            'key' => 'op',
        ]);
        $container->register('key_management.backup', EncrypterInterface::class)->addTag('key_management.client', [
            'key' => 'backup',
        ]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The KMS client "aws" named by the "heidi.keys.kms" configuration is not registered in "key_management.clients": the registered ones are "op", "backup".');

        // When
        new KmsClientPass()->process($container);
    }

    #[Test]
    public function aNameNoClientAtAllAnswersToSaysSo(): void
    {
        // Given
        $container = self::container('op');

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The KMS client "op" named by the "heidi.keys.kms" configuration is not registered in "key_management.clients": no client is registered at all.');

        // When
        new KmsClientPass()->process($container);
    }

    /**
     * A container the bundle was not loaded into has no alias to check, and the pass has nothing to say
     * about it.
     */
    #[Test]
    public function aContainerWithoutTheBundleIsLeftAlone(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        new KmsClientPass()->process($container);

        // Then
        static::assertFalse($container->hasAlias('heidi.kms'));
    }

    private static function container(string $client): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setAlias('heidi.kms', 'key_management.' . $client);

        return $container;
    }
}
