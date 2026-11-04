<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Interaction;

use function array_keys;
use function array_map;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Interaction\ConsentPage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ConsentPageTest extends TestCase
{
    /**
     * OIDC Registration §2
     */
    #[Test]
    public function itCarriesThePagesTheClientRegistered(): void
    {
        // When
        $page = new ConsentPage(self::presentation());

        // Then
        static::assertSame(
            [
                'policy_uri' => 'https://rp.example/privacy',
                'tos_uri' => 'https://rp.example/terms',
                'client_uri' => 'https://rp.example/',
            ],
            array_map(static fn (ClientUri $uri): string => $uri->value, $page->links),
        );
    }

    /**
     * @param list<string> $members
     */
    #[Test]
    #[DataProvider('providePresentations')]
    public function itCarriesOnlyThePagesTheClientRegistered(ClientPresentation $presentation, array $members): void
    {
        // When
        $page = new ConsentPage($presentation);

        // Then
        static::assertSame($members, array_keys($page->links));
    }

    /**
     * @return iterable<string, array{ClientPresentation, list<string>}>
     */
    public static function providePresentations(): iterable
    {
        yield 'everything of OIDC Registration section 2' => [self::presentation(), ['policy_uri', 'tos_uri', 'client_uri']];

        yield 'a name and nothing else' => [new ClientPresentation('An application'), []];

        yield 'a logo alone, which is no link' => [
            new ClientPresentation('An application', logoUri: new ClientUri('https://rp.example/logo.png')),
            [],
        ];

        yield 'a policy alone' => [
            new ClientPresentation('An application', policyUri: new ClientUri('https://rp.example/privacy')),
            ['policy_uri'],
        ];

        yield 'terms alone' => [
            new ClientPresentation('An application', tosUri: new ClientUri('https://rp.example/terms')),
            ['tos_uri'],
        ];

        yield 'a home page alone' => [
            new ClientPresentation('An application', new ClientUri('https://rp.example/')),
            ['client_uri'],
        ];
    }

    /**
     * CSP Level 3 §6.1, RFC 6454 §3.2
     */
    #[Test]
    public function itNamesTheOriginTheLogoOfTheClientIsServedFrom(): void
    {
        // When / Then
        static::assertSame(['https://rp.example'], new ConsentPage(self::presentation())->imageOrigins);
    }

    #[Test]
    public function itNamesNoOriginForAClientThatRegisteredNoLogo(): void
    {
        // When / Then
        static::assertSame([], new ConsentPage(new ClientPresentation('An application'))->imageOrigins);
    }

    /**
     * RFC 6454 §3.2
     */
    #[Test]
    #[DataProvider('provideLogoUris')]
    public function itNamesTheOriginOfTheLogoAndNeverItsUrl(string $logoUri, string $origin): void
    {
        // When
        $page = new ConsentPage(new ClientPresentation('An application', logoUri: new ClientUri($logoUri)));

        // Then
        static::assertSame([$origin], $page->imageOrigins);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideLogoUris(): iterable
    {
        yield 'a path' => ['https://rp.example/assets/logo.png', 'https://rp.example'];

        yield 'a port' => ['https://rp.example:8443/logo.png', 'https://rp.example:8443'];

        yield 'a query' => ['https://rp.example/logo?size=64', 'https://rp.example'];

        yield 'a host of its own' => ['https://cdn.rp.example/logo.png', 'https://cdn.rp.example'];

        yield 'a loopback host (RFC 8252 §7.3)' => ['http://127.0.0.1:8080/logo.png', 'http://127.0.0.1:8080'];
    }

    private static function presentation(): ClientPresentation
    {
        return new ClientPresentation(
            'An application',
            new ClientUri('https://rp.example/'),
            new ClientUri('https://rp.example/logo.png'),
            new ClientUri('https://rp.example/privacy'),
            new ClientUri('https://rp.example/terms'),
            ['ops@rp.example'],
        );
    }
}
