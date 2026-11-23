<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\OutboundGuardInterface;
use App\Http\ThirdPartyRequestsPass;
use App\Http\LogoutTokenSender;
use App\Push\WebPushSender;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class ThirdPartyRequestsPassTest extends TestCase
{
    #[Test]
    public function aServiceTaggedIsHandedTheClientOfTheApplicationGuarded(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->register(LogoutTokenSender::class, LogoutTokenSender::class)->addTag(ThirdPartyRequestsPass::TAG);

        // When
        new ThirdPartyRequestsPass()->process($container);

        // Then
        $client = $container->getDefinition(LogoutTokenSender::class)->getArgument('$http');
        static::assertInstanceOf(Definition::class, $client);
        static::assertEquals([new Reference(OutboundGuardInterface::class), 'guard'], $client->getFactory());
        static::assertEquals([new Reference('http_client')], $client->getArguments());
    }

    #[Test]
    public function aServiceTaggedKeepsTheClientItWasHandedGuarded(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container
            ->register(WebPushSender::class, WebPushSender::class)
            ->setArgument('$http', new Reference('beffroi.web_push.http_client'))
            ->addTag(ThirdPartyRequestsPass::TAG);

        // When
        new ThirdPartyRequestsPass()->process($container);

        // Then
        $client = $container->getDefinition(WebPushSender::class)->getArgument('$http');
        static::assertInstanceOf(Definition::class, $client);
        static::assertEquals([new Reference('beffroi.web_push.http_client')], $client->getArguments());
    }

    #[Test]
    public function aServiceNotTaggedKeepsItsArguments(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->register(LogoutTokenSender::class, LogoutTokenSender::class);

        // When
        new ThirdPartyRequestsPass()->process($container);

        // Then
        static::assertSame([], $container->getDefinition(LogoutTokenSender::class)->getArguments());
    }
}
