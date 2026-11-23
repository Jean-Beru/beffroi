<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\CrossSitePost;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use function http_build_query;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml S-28, OIDC Core §3.1.2.1, RP-Initiated Logout §2
 */
final class CrossSitePostTest extends BrowserTestCase
{
    private const string POSTED_AGAIN = '/authorize?' . CrossSitePost::MARKER . '=1';

    private const string ENGLISH_BROWSER = 'en-US,en;q=0.9';

    /**
     * RP-Initiated Logout §2
     */
    private const string LOGOUT = 'client_id=oidc-demo&post_logout_redirect_uri=https%3A%2F%2Fdemo.test%2F&state=after-logout';

    private const array FRENCH_PAGE = [
        'fr',
        'Connexion en cours',
        'Continuer',
    ];

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        parent::setUp();
        $this->session = $this->signIn(self::user('alice'));
    }

    /**
     * S-28
     */
    #[Test]
    public function aRequestPostedFromAnotherSiteIsAnsweredFromTheSession(): void
    {
        // Given
        $this->postedFromAnotherSite('/authorize', self::body());

        // When
        $this->postedAgain();

        // Then
        static::assertStringStartsWith(
            'https://demo.test/login/check?code=',
            (string) $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * S-28
     */
    #[Test]
    public function thePagePostsTheBodyAsItCame(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . '&state=second+state&caf%C3%A9=a%20%3C%22value%22%3E');

        // Then
        static::assertSame(
            [
                self::POSTED_AGAIN,
                [...self::pairs(), ['state', 'second state'], ["caf\u{e9}", 'a <"value">']],
            ],
            $this->page(),
        );
    }

    /**
     * S-28
     */
    #[Test]
    public function thePageSetsNoCookie(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body());

        // Then
        static::assertSame([], $this->browser->getResponse()->headers->getCookies());
    }

    /**
     * S-28, bindings.md section 6.7
     */
    #[Test]
    public function thePageCarriesItsPolicyAndIsNeverCached(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [
                "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; base-uri 'none'; frame-ancestors 'none'",
                true,
                true,
                'no-cache',
                CrossSitePost::SCRIPT,
                1,
            ],
            [
                $response->headers->get('Content-Security-Policy'),
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
                $this->browser->getCrawler()->filter('script')->text(),
                $this->browser->getCrawler()->filter('noscript button[type="submit"]')->count(),
            ],
        );
    }

    /**
     * S-28, Architecture §5.7
     */
    #[Test]
    public function thePageSpeaksTheLanguageOfTheBrowser(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body(), ['HTTP_ACCEPT_LANGUAGE' => 'fr']);

        // Then
        static::assertSame(self::FRENCH_PAGE, $this->words());
    }

    /**
     * S-28, OIDC Core §3.1.2.1, Architecture §5.7
     */
    #[Test]
    public function theUiLocalesOfThePostedBodyComeBeforeTheBrowser(): void
    {
        // When
        $this->postedFromAnotherSite(
            '/authorize',
            http_build_query(self::authorizationParameters('oidc-demo', ['ui_locales' => 'fr'])),
            ['HTTP_ACCEPT_LANGUAGE' => self::ENGLISH_BROWSER],
        );

        // Then
        static::assertSame(self::FRENCH_PAGE, $this->words());
    }

    /**
     * S-28
     */
    #[Test]
    #[DataProvider('provideUiLocalesTheEndpointRefuses')]
    public function aUiLocalesTheEndpointRefusesLeavesTheLanguageOfTheBrowser(string $tail): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . $tail, ['HTTP_ACCEPT_LANGUAGE' => 'fr']);

        // Then
        static::assertSame(self::FRENCH_PAGE, $this->words());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUiLocalesTheEndpointRefuses(): iterable
    {
        yield 'a value that is no language tag' => ['&ui_locales=en_GB'];
        yield 'a repeated parameter' => ['&ui_locales=en&ui_locales=en'];
    }

    /**
     * S-28
     */
    #[Test]
    public function aRequestPostedAgainIsNotPostedAThirdTime(): void
    {
        // When
        $this->postedFromAnotherSite(self::POSTED_AGAIN, self::body(), ['HTTP_SEC_FETCH_SITE' => 'same-origin']);

        // Then
        self::assertServedAsItCame();
    }

    /**
     * S-28, "The marker"
     */
    #[Test]
    public function aPostFromAnotherSiteThatForgesTheMarkerIsPostedAgainWithoutASession(): void
    {
        // When
        $this->postedFromAnotherSite(self::POSTED_AGAIN, self::body());

        // Then
        static::assertSame([self::POSTED_AGAIN, []], [$this->page()[0], $this->browser->getResponse()->headers->getCookies()]);
    }

    /**
     * S-28
     */
    #[Test]
    public function aLogoutPostedFromAnotherSiteIsPostedAgain(): void
    {
        // When
        $this->postedFromAnotherSite('/logout', self::LOGOUT);

        // Then
        static::assertSame(
            ['/logout?' . CrossSitePost::MARKER . '=1', []],
            [$this->page()[0], $this->browser->getResponse()->headers->getCookies()],
        );
    }

    /**
     * S-28, RP-Initiated Logout §2
     */
    #[Test]
    public function aLogoutPostedAgainAsksTheUserOfTheSession(): void
    {
        // Given
        $this->postedFromAnotherSite('/logout', self::LOGOUT);

        // When
        $this->postedAgain();

        // Then
        static::assertSame(
            [Response::HTTP_OK, 'no_hint'],
            [$this->browser->getResponse()->getStatusCode(), $this->browser->getCrawler()->filter('[data-reason]')->attr('data-reason')],
        );
    }

    /**
     * S-28
     */
    #[Test]
    public function aConfirmationForgedOnAnotherSiteEndsNothing(): void
    {
        // Given
        $this->postedFromAnotherSite('/logout', self::LOGOUT . '&confirm=yes&_token=forged');

        // When
        $this->postedAgain();

        // Then
        $kept = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($this->session->id) ?? static::fail('The session is gone.');
        static::assertSame([Response::HTTP_FORBIDDEN, false], [$this->browser->getResponse()->getStatusCode(), $kept->hasEnded()]);
    }

    /**
     * S-28
     */
    #[Test]
    public function theMarkerIsAddedAfterTheQueryOfTheRequest(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize?x=y', self::body());

        // Then
        static::assertSame('/authorize?x=y&' . CrossSitePost::MARKER . '=1', $this->page()[0]);
    }

    /**
     * S-28
     */
    #[Test]
    #[DataProvider('provideSitesThatAreNotAnother')]
    public function aPostNotFromAnotherSiteIsServedAsItCame(?string $site): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body(), ['HTTP_SEC_FETCH_SITE' => $site]);

        // Then
        self::assertServedAsItCame();
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideSitesThatAreNotAnother(): iterable
    {
        yield 'same-origin' => ['same-origin'];
        yield 'same-site' => ['same-site'];
        yield 'none' => ['none'];
        yield 'no header' => [null];
    }

    /**
     * S-28
     */
    #[Test]
    public function aPostCarryingTheCookieIsServedDirectly(): void
    {
        // When
        $this->postedFromAnotherSiteWithTheCookie('/authorize', self::body());

        // Then
        static::assertStringStartsWith(
            'https://demo.test/login/check?code=',
            (string) $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * S-28
     */
    #[Test]
    #[DataProvider('provideBodiesThatDoNotComeBack')]
    public function aBodyThatWouldNotComeBackIsServedAsItCame(string $tail): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . $tail);

        // Then
        self::assertServedAsItCame();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBodiesThatDoNotComeBack(): iterable
    {
        yield 'a line feed alone' => ['&x=a%0Ab'];
        yield 'a carriage return alone' => ['&x=a%0Db'];
        yield 'a NUL' => ['&x=a%00b'];
        yield 'a delete' => ['&x=a%7Fb'];
        yield 'bytes that are not UTF-8' => ['&x=%C3%28'];
        yield 'a name that is not UTF-8' => ['&%C3%28=b'];
        yield 'a name with a control character' => ['&a%01=b'];
        yield 'a field the browser names its encoding in' => ['&_charset_=b'];
        yield 'a field without a name' => ['&=b'];
    }

    /**
     * S-28, HTML "preprocessing the input stream", "converting an entry list to a list of name-value pairs"
     */
    #[Test]
    public function aLineBreakWrittenAsCrLfIsPostedAgain(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . '&login_hint=a%0D%0Ab%09c');

        // Then
        static::assertStringContainsString(
            "<input type=\"hidden\" name=\"login_hint\" value=\"a\r\nb\tc\">",
            self::string($this->browser->getResponse()->getContent()),
        );
    }

    /**
     * S-28
     */
    #[Test]
    public function aPairWithoutValueIsPostedAgainEmpty(): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body() . '&&display');

        // Then
        static::assertSame(['display', ''], $this->page()[1][8] ?? null);
    }

    /**
     * S-28, RFC 9110 §8.3.1
     */
    #[Test]
    #[DataProvider('provideMediaTypesOfAForm')]
    public function aFormIsKnownByItsMediaTypeAlone(string $contentType): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', self::body(), ['CONTENT_TYPE' => $contentType]);

        // Then
        static::assertSame(self::POSTED_AGAIN, $this->page()[0]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMediaTypesOfAForm(): iterable
    {
        yield 'in capitals' => ['Application/X-WWW-Form-Urlencoded'];
        yield 'with a charset' => [' application/x-www-form-urlencoded ; charset=UTF-8'];
    }

    /**
     * S-28
     */
    #[Test]
    #[DataProvider('provideBodiesThatAreNotForms')]
    public function aBodyThatIsNotAFormIsServedAsItCame(string $contentType, string $body): void
    {
        // When
        $this->postedFromAnotherSite('/authorize', $body, ['CONTENT_TYPE' => $contentType]);

        // Then
        static::assertNotSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBodiesThatAreNotForms(): iterable
    {
        yield 'plain text' => ['text/plain', self::body()];
        yield 'multipart' => ['multipart/form-data; boundary=x', "--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--x--\r\n"];
        yield 'an empty form' => ['application/x-www-form-urlencoded', ''];
    }

    /**
     * S-28
     */
    #[Test]
    public function aGetFromAnotherSiteIsServedAsItCame(): void
    {
        // Given
        $this->browser->getCookieJar()->clear();

        // When
        $this->browser->request(
            'GET',
            '/authorize',
            self::authorizationParameters('oidc-demo'),
            [],
            [
                'HTTP_SEC_FETCH_SITE' => 'cross-site',
            ],
        );

        // Then
        self::assertServedAsItCame();
    }

    private function assertServedAsItCame(): void
    {
        static::assertStringStartsWith('/login?interaction=', (string) $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * @return array{string, list<array{string, string}>}
     */
    private function page(): array
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $form = $this->browser->getCrawler()->filter('form')->first();
        $fields = $form->filter('input[type="hidden"]')->each(
            static fn (Crawler $input): array => [(string) $input->attr('name'), (string) $input->attr('value')],
        );

        return [(string) $form->attr('action'), $fields];
    }

    /**
     * @return array{string, string, string}
     */
    private function words(): array
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $crawler = $this->browser->getCrawler();

        return [
            (string) $crawler->filter('html')->attr('lang'),
            $crawler->filter('title')->text(),
            $crawler->filter('noscript button')->text(),
        ];
    }

    private static function body(): string
    {
        return http_build_query(self::authorizationParameters('oidc-demo'));
    }

    /**
     * @return list<array{string, string}>
     */
    private static function pairs(): array
    {
        $pairs = [];
        foreach (self::authorizationParameters('oidc-demo') as $name => $value) {
            $pairs[] = [$name, $value];
        }

        return $pairs;
    }
}
