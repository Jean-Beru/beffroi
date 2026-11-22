<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Oidc\Domain\Authorization\FormPostResponse;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth 2.0 Form Post Response Mode §2, OIDC Core §3.1.2.6
 */
final class FormPostResponseTest extends BrowserTestCase
{
    private const string SCRIPT_HASH = 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ=';

    /**
     * RFC 6749 §4.1.2, RFC 9207 §2
     */
    #[Test]
    public function theCodeIsPostedWithTheStateAndTheIssuer(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/authorize', self::formPostParameters());

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('https://demo.test/login/check', $crawler->filter('form')->attr('action'));
        static::assertSame('post', $crawler->filter('form')->attr('method'));
        $posted = self::postedFields($crawler);
        static::assertArrayHasKey('code', $posted);
        static::assertSame('state-of-the-client', $posted['state']);
        static::assertSame('https://op.test', $posted['iss']);
    }

    /**
     * Form Post Response Mode §2
     */
    #[Test]
    public function nothingOfTheAnswerIsWrittenInAUrl(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::formPostParameters());

        // Then
        $response = $this->browser->getResponse();
        static::assertFalse($response->headers->has('Location'));
        static::assertStringNotContainsString('code=', self::string($response->getContent()));
    }

    /**
     * Form Post Response Mode §2, RFC 6749 §5.1
     */
    #[Test]
    public function thePageIsNotCacheable(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::formPostParameters());

        // Then
        static::assertTrue($this->browser->getResponse()->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * CSP Level 3 §6.1
     */
    #[Test]
    public function thePolicyNamesTheScriptByItsHash(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::formPostParameters());

        // Then
        static::assertSame(
            sprintf("default-src 'none'; script-src '%s'; form-action https://demo.test; base-uri 'none'; frame-ancestors 'none'", self::SCRIPT_HASH),
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    #[Test]
    public function thePageCarriesTheScriptThePolicyNames(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/authorize', self::formPostParameters());

        // Then
        static::assertSame(FormPostResponse::SCRIPT, $crawler->filter('script')->text(null, false));
    }

    /**
     * Form Post Response Mode §2
     */
    #[Test]
    public function thePageOffersASubmitButtonToABrowserWithoutScripting(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/authorize', self::formPostParameters());

        // Then
        static::assertSame('Continue', $crawler->filter('form button[type=submit]')->text());
    }

    /**
     * OIDC Core §3.1.2.6, RFC 9207 §2
     */
    #[Test]
    public function aRefusalIsPostedToo(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/authorize', self::formPostParameters([
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertFalse($this->browser->getResponse()->headers->has('Location'));
        static::assertSame(
            [
                'error' => 'invalid_request',
                'error_description' => 'The code_challenge parameter is missing (RFC 7636 section 4.3).',
                'state' => 'state-of-the-client',
                'iss' => 'https://op.test',
            ],
            self::postedFields($crawler),
        );
    }

    /**
     * RFC 9700 §4.1
     */
    #[Test]
    public function anErrorOfTheFirstStageIsStillAPage(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::formPostParameters([
            'client_id' => 'unknown-client',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function theModeSurvivesTheLoginAndTheConsentPages(): void
    {
        // Given
        $this->browser->request('GET', '/authorize', self::formPostParameters(clientId: 'native-app'));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->signIn(self::user('alice'));
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // When
        $crawler = $this->browser->submit($crawler->selectButton('Allow')->form());

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('http://127.0.0.1/callback', $crawler->filter('form')->attr('action'));
        static::assertArrayHasKey('code', self::postedFields($crawler));
    }

    /**
     * Multiple Response Type Encoding Practices §2.1
     */
    #[Test]
    public function aModeTheProviderDoesNotServeIsRefusedInTheDefaultMode(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::formPostParameters([
            'response_mode' => 'fragment',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('unsupported_response_mode', self::redirectedQuery($response)['error']);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aResponseTypeOtherThanCodeIsRefusedWhateverTheMode(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/authorize', self::formPostParameters([
            'response_type' => 'id_token',
        ]));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('unsupported_response_type', self::postedFields($crawler)['error']);
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    private static function formPostParameters(array $parameters = [], string $clientId = 'oidc-demo'): array
    {
        return self::authorizationParameters(
            $clientId,
            $parameters
            + [
                'response_mode' => 'form_post',
            ],
        );
    }

    /**
     * @return array<string, string>
     */
    private static function postedFields(Crawler $page): array
    {
        $fields = [];
        foreach ($page->filter('form input[type=hidden]')->extract(['name', 'value']) as $field) {
            static::assertIsArray($field);
            $fields[self::string($field[0] ?? null)] = self::string($field[1] ?? null);
        }

        return $fields;
    }
}
