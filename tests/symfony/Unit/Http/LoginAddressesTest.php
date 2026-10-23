<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Http\LoginTarget;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Environment;

/**
 * beffroi/saml S-61: the step of the address of the login a page of the provider asks for is asked again for the next
 * page that asks for one, whatever was typed for the login before.
 */
final class LoginAddressesTest extends TestCase
{
    #[Test]
    public function aPageThatAsksForALoginAsksForTheAddressAgain(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->pass($httpSession, null, 'bob@umbrella.example');
        $urls = static::createStub(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturn('/login');
        $targets = new LoginTarget(new InteractionPages(static::createStub(Environment::class), $urls), $addresses);

        // When
        $targets->sendToLogin($httpSession, 'beffroi_interaction_account');

        // Then
        static::assertFalse($addresses->passed($httpSession, null));
    }
}
