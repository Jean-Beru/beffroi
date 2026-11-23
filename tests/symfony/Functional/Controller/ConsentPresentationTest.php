<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Registration §2
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
     * OIDC Registration §2
     *
     * @param array<string, string> $registered
     * @param list<string> $shown the "data-client" codes of the page, in the order it shows them
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

    #[Test]
    public function theNameOfTheClientIsSetApartInEverySentenceThatCarriesIt(): void
    {
        // Given
        $clientId = $this->registerClient([
            'client_name' => 'An application of the ecosystem',
            'policy_uri' => self::POLICY_URI,
        ]);

        // When
        $names = $this->consentPageOf($clientId)->filter('main b[data-client-name]');

        // Then
        static::assertSame(['An application of the ecosystem', 'An application of the ecosystem'], $names->extract(['_text']));
    }

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

    #[Test]
    public function thePageOfAClientThatRegisteredALogoCarriesThePolicyOfItsDeployment(): void
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
        self::assertInteractionHeaders($this->browser->getResponse());
    }

    /**
     * Architecture §5.7
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
                'Conditions d\'utilisation de Une application de l’écosystème',
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
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
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
     * OIDC Core §3.1.2.1
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
