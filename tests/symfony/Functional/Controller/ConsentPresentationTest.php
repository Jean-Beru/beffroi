<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Registration §2: what a client registered about itself reaches the user who is about to authorise
 * it. The clients here register themselves, which is the one way every combination of the five members
 * exists, and it is the way the three modules of the Dynamic OP plan make theirs
 * (oidcc-registration-logo-uri, -policy-uri, -tos-uri).
 */
final class ConsentPresentationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    private const string LOGO_URI = 'https://cdn.rp.test/logo.png';

    private const string POLICY_URI = 'https://rp.test/privacy';

    private const string TOS_URI = 'https://rp.test/terms';

    private const string CLIENT_URI = 'https://rp.test/';

    /**
     * The five members of OIDC Registration §2 a user reads, every combination of them: all five, none of
     * them, and each one alone. What the page carries is what the client registered and nothing else, in
     * the order it shows them, so a client that registered none of them renders no empty element.
     *
     * @param array<string, string> $registered what the client registers about itself
     * @param list<string> $shown the "data-client" codes the page carries, in the order it shows them
     */
    #[Test]
    #[DataProvider('provideRegistrations')]
    public function theConsentPageShowsWhatTheClientRegisteredAboutItself(array $registered, array $shown, string $name): void
    {
        // Given
        $clientId = $this->registerClient($registered);

        // When
        $crawler = $this->consentPageOf($clientId);

        // Then
        static::assertSame($shown, $crawler->filter('[data-client]')->extract(['data-client']));
        static::assertStringContainsString($name === '' ? $clientId : $name, self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * @return iterable<string, array{array<string, string>, list<string>, string}>
     */
    public static function provideRegistrations(): iterable
    {
        yield 'the five of OIDC Registration section 2' => [
            [
                'client_name' => 'An application of the ecosystem',
                'logo_uri' => self::LOGO_URI,
                'policy_uri' => self::POLICY_URI,
                'tos_uri' => self::TOS_URI,
                'client_uri' => self::CLIENT_URI,
            ],
            ['logo', 'policy_uri', 'tos_uri', 'client_uri'],
            'An application of the ecosystem',
        ];

        yield 'none of the five' => [[], [], ''];

        yield 'a name alone' => [
            [
                'client_name' => 'An application of the ecosystem',
            ],
            [],
            'An application of the ecosystem',
        ];

        yield 'a logo alone' => [
            [
                'logo_uri' => self::LOGO_URI,
            ],
            ['logo'],
            '',
        ];

        yield 'a policy alone' => [
            [
                'policy_uri' => self::POLICY_URI,
            ],
            ['policy_uri'],
            '',
        ];

        yield 'terms alone' => [
            [
                'tos_uri' => self::TOS_URI,
            ],
            ['tos_uri'],
            '',
        ];

        yield 'a home page alone' => [
            [
                'client_uri' => self::CLIENT_URI,
            ],
            ['client_uri'],
            '',
        ];
    }

    /**
     * The image is the URL the client registered, loaded by the browser of the user with no referrer, and
     * named for whoever does not see it.
     */
    #[Test]
    public function theLogoIsLoadedFromTheClientWithNoReferrer(): void
    {
        // Given
        $clientId = $this->registerClient([
            'client_name' => 'An application of the ecosystem',
            'logo_uri' => self::LOGO_URI,
        ]);

        // When
        $logo = $this->consentPageOf($clientId)->filter('img[data-client="logo"]');

        // Then
        static::assertSame(self::LOGO_URI, $logo->attr('src'));
        static::assertSame('no-referrer', $logo->attr('referrerpolicy'));
        static::assertSame('Logo of An application of the ecosystem', $logo->attr('alt'));
    }

    /**
     * The three pages are links, each said in the words of what it is, opened beside the interaction
     * rather than in place of it and carrying nothing of this provider to the client.
     */
    #[Test]
    public function thePagesOfTheClientAreLinksThatCarryNothingBack(): void
    {
        // Given
        $clientId = $this->registerClient([
            'policy_uri' => self::POLICY_URI,
            'tos_uri' => self::TOS_URI,
            'client_uri' => self::CLIENT_URI,
        ]);

        // When
        $links = $this->consentPageOf($clientId)->filter('a[data-client]');

        // Then
        static::assertSame([self::POLICY_URI, self::TOS_URI, self::CLIENT_URI], $links->extract(['href']));
        static::assertSame(['_blank', '_blank', '_blank'], $links->extract(['target']));
        static::assertSame(['noreferrer noopener', 'noreferrer noopener', 'noreferrer noopener'], $links->extract(['rel']));
    }

    /**
     * CSP Level 3 §6.1: the page loads the logo of the client that is asking and no other image, whatever
     * else that client registered.
     */
    #[Test]
    public function thePageAllowsTheOriginOfTheLogoAndNoOther(): void
    {
        // Given
        $clientId = $this->registerClient([
            'logo_uri' => self::LOGO_URI,
            'policy_uri' => self::POLICY_URI,
            'client_uri' => self::CLIENT_URI,
        ]);

        // When
        $this->consentPageOf($clientId);

        // Then
        self::assertInteractionHeaders(
            $this->browser->getResponse(),
            "img-src 'self' https://cdn.rp.test; frame-ancestors 'none'",
        );
    }

    /**
     * A client that registered no logo leaves a page that loads no image of anybody's.
     */
    #[Test]
    public function thePageOfAClientWithNoLogoNamesNoOrigin(): void
    {
        // Given
        $clientId = $this->registerClient([
            'policy_uri' => self::POLICY_URI,
        ]);

        // When
        $this->consentPageOf($clientId);

        // Then
        self::assertInteractionHeaders(
            $this->browser->getResponse(),
            "img-src 'self'; frame-ancestors 'none'",
        );
    }

    /**
     * Architecture §5.7: what the page gained is read in the language of the interaction, like everything
     * else on it.
     */
    #[Test]
    public function whatTheClientRegisteredIsSaidInTheLanguageOfTheInteraction(): void
    {
        // Given
        $clientId = $this->registerClient([
            'client_name' => 'Une application de l’écosystème',
            'policy_uri' => self::POLICY_URI,
            'tos_uri' => self::TOS_URI,
            'client_uri' => self::CLIENT_URI,
        ]);

        // When
        $links = $this->consentPageOf($clientId, 'fr')->filter('a[data-client]');

        // Then
        static::assertSame(
            [
                'Comment Une application de l’écosystème utilise vos données',
                'Conditions d’utilisation de Une application de l’écosystème',
                'Site de Une application de l’écosystème',
            ],
            $links->extract(['_text']),
        );
    }

    /**
     * @param array<string, string> $members
     */
    private function registerClient(array $members): string
    {
        $issuedAt = self::currentSecond();
        self::service('test.heidi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::TOKEN),
                'The team that integrates',
                1,
                $issuedAt,
                $issuedAt->modify('+1 day'),
            ));
        self::reload();
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode(
                $members
                + [
                    'redirect_uris' => [self::REDIRECT_URI],
                    'scope' => 'openid profile',
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['client_id']);
    }

    /**
     * The consent page of an authorization this client began, in the language the request asked for
     * (OIDC Core §3.1.2.1), which the interaction records once and every page of it then speaks.
     */
    private function consentPageOf(string $clientId, ?string $uiLocales = null): Crawler
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => self::REDIRECT_URI,
            'ui_locales' => $uiLocales,
        ]));
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }
}
