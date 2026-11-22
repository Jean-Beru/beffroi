<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Key;

use App\Key\KmsClientPass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\KeyManagement\EncrypterInterface;

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
        static::assertSame('key_management.op', (string) $container->getAlias('beffroi.kms'));
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
        $this->expectExceptionMessageIs('The KMS client "aws" named by the "beffroi.keys.kms" configuration is not registered in "key_management.clients": the registered ones are "op", "backup".');

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
        $this->expectExceptionMessageIs('The KMS client "op" named by the "beffroi.keys.kms" configuration is not registered in "key_management.clients": no client is registered at all.');

        // When
        new KmsClientPass()->process($container);
    }

    #[Test]
    public function aContainerWithoutTheProviderIsLeftAlone(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        new KmsClientPass()->process($container);

        // Then
        static::assertFalse($container->hasAlias('beffroi.kms'));
    }

    private static function container(string $client): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setAlias('beffroi.kms', 'key_management.' . $client);

        return $container;
    }
}
