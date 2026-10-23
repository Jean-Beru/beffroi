<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Environment;

/**
 * beffroi/saml S-61: the step of the address of the login a page of the provider asks for is asked again for the next
 * page that asks for one, whatever was typed for the login before. S-68: the address of a federated domain is kept for
 * the sign-on of that login alone, taken once.
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

    /**
     * S-68: the address sent on for a login is what its sign-on takes.
     */
    #[Test]
    public function theSignOnTakesTheAddressSentOn(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->sendOn($httpSession, null, 'alice@Bücher.example');

        // When / Then
        static::assertSame('alice@Bücher.example', $addresses->takeSent($httpSession, null));
    }

    /**
     * S-68: an address is taken once, and a second sign-on of the same login takes none.
     */
    #[Test]
    public function anAddressIsTakenOnce(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $interaction = self::interaction();
        $addresses->sendOn($httpSession, $interaction, 'alice@example.org');
        $addresses->takeSent($httpSession, $interaction);

        // When / Then
        static::assertNull($addresses->takeSent($httpSession, $interaction));
    }

    /**
     * S-68: the address of one login is not taken by the sign-on of another, whose address is its own.
     */
    #[Test]
    public function eachLoginKeepsItsOwnAddress(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $interaction = self::interaction();
        $addresses->sendOn($httpSession, $interaction, 'alice@example.org');
        $addresses->sendOn($httpSession, null, 'bob@example.org');

        // When / Then
        static::assertSame(['alice@example.org', null], [
            $addresses->takeSent($httpSession, $interaction),
            $addresses->takeSent($httpSession, self::interaction()),
        ]);
    }

    /**
     * S-68, section 7: a browser keeps the addresses of eight logins at most, the oldest forgotten first, the address
     * sent on again for a login counting as the newest.
     */
    #[Test]
    public function eightAddressesAreKeptAtMost(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $first = self::interaction();
        $second = self::interaction();
        $addresses->sendOn($httpSession, $first, 'first@example.org');
        $addresses->sendOn($httpSession, $second, 'second@example.org');
        $addresses->sendOn($httpSession, $first, 'first@example.org');

        // When
        for ($login = 0; $login < (LoginAddresses::MAX_KEPT - 1); ++$login) {
            $addresses->sendOn($httpSession, self::interaction(), 'other@example.org');
        }

        // Then
        static::assertSame(['first@example.org', null], [$addresses->takeSent($httpSession, $first), $addresses->takeSent($httpSession, $second)]);
    }

    /**
     * S-68: back to the step of the address, the address sent on for that login is forgotten with what was typed.
     */
    #[Test]
    public function theAddressSentOnIsForgottenWithTheStep(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->sendOn($httpSession, null, 'alice@example.org');

        // When
        $addresses->forget($httpSession, null);

        // Then
        static::assertNull($addresses->takeSent($httpSession, null));
    }

    /**
     * S-68: what the HTTP session holds under the key of the addresses and is no address of a login is read as none.
     */
    #[Test]
    #[DataProvider('provideStoredValuesThatAreNoAddresses')]
    public function whatIsNoAddressOfALoginIsNone(mixed $stored): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $httpSession->set(LoginAddresses::SENT_SESSION_KEY, $stored);

        // When / Then
        static::assertNull(new LoginAddresses()->takeSent($httpSession, null));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideStoredValuesThatAreNoAddresses(): iterable
    {
        yield 'no map' => [':page'];
        yield 'an address that is no string' => [[':page' => ['alice@example.org']]];
    }

    private static function interaction(): Interaction
    {
        $tenant = Fixtures::tenant();

        return new Interaction(
            Secrets::draw(),
            $tenant,
            Requests::authorization(Clients::public($tenant)),
            null,
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
    }
}
