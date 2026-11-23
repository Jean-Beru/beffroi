<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Push;

use App\Push\WebPushHttpClientPass;
use App\Push\WebPushSender;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class WebPushHttpClientPassTest extends TestCase
{
    #[Test]
    public function theSenderIsHandedAClientOfItsOwn(): void
    {
        // Given
        $container = self::container();

        // When
        new WebPushHttpClientPass()->process($container);

        // Then
        static::assertEquals(new Reference(WebPushHttpClientPass::CLIENT), $container->getDefinition(WebPushSender::class)->getArgument('$http'));
    }

    #[Test]
    public function itsClientIsBuiltAsTheTransportOfTheApplicationIs(): void
    {
        // Given
        $container = self::container();

        // When
        new WebPushHttpClientPass()->process($container);

        // Then
        $transport = $container->getDefinition('http_client.transport');
        $client = $container->getDefinition(WebPushHttpClientPass::CLIENT);
        static::assertSame($transport->getFactory(), $client->getFactory());
        static::assertSame($transport->getArguments(), $client->getArguments());
        static::assertSame(['kernel.reset' => [['method' => 'reset']]], $client->getTags());
    }

    #[Test]
    public function itsClientLogsNoRequest(): void
    {
        // Given
        $container = self::container();

        // When
        new WebPushHttpClientPass()->process($container);

        // Then
        static::assertSame([], $container->getDefinition(WebPushHttpClientPass::CLIENT)->getMethodCalls());
    }

    #[Test]
    public function anApplicationWithNoHttpClientIsGivenNone(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->register(WebPushSender::class, WebPushSender::class);

        // When
        new WebPushHttpClientPass()->process($container);

        // Then
        static::assertFalse($container->hasDefinition(WebPushHttpClientPass::CLIENT));
    }

    private static function container(): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container
            ->register('http_client.transport', HttpClientInterface::class)
            ->setFactory([HttpClient::class, 'create'])
            ->setArguments([['resolve' => ['demo.localhost' => '172.17.0.1']], 6, 0])
            ->addMethodCall('setLogger', [new Reference('logger', ContainerInterface::IGNORE_ON_INVALID_REFERENCE)])
            ->addTag('monolog.logger', ['channel' => 'http_client'])
            ->addTag('kernel.reset', ['method' => 'reset']);
        $container->register(WebPushSender::class, WebPushSender::class);

        return $container;
    }
}
