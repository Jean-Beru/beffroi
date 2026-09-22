<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Oidc\Domain\Authorization\FormPostResponse;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth 2.0 Form Post Response Mode §2, the first success criterion of spike 4 (issue #138): a client
 * that asks for "form_post" gets the answer of the authorization endpoint as a page whose form the
 * browser posts to the redirect URI, never as a redirection. A refusal is posted the same way, the mode
 * of the request being the mode of everything it hears back (OIDC Core §3.1.2.6).
 */
final class FormPostResponseTest extends BrowserTestCase
{
    /**
     * The hash the Content-Security-Policy of the page names, over the one script the page carries.
     */
    private const string SCRIPT_HASH = 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ=';

    /**
     * RFC 6749 §4.1.2 and RFC 9207 §2: the code, the state and the issuer, every one of them a hidden
     * field of a form whose action is the registered redirect URI.
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
     * Form Post Response Mode §2: the answer is a page, so nothing of it is ever written in a URL, in an
     * address bar, in a history or in an access log.
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
     * Form Post Response Mode §2 and RFC 6749 §5.1: a page carrying an authorization code is never
     * stored, by the browser or by anything between.
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
     * CSP Level 3 §6.1: the one script that submits the form is named by its hash, so the page allows
     * that script and no other; nothing else loads and nothing frames the page.
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

    /**
     * The script the policy names is the one the page carries, byte for byte: a page whose script the
     * hash does not cover would never submit itself.
     */
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
     * Form Post Response Mode §2: a browser that runs no script is given the button that posts the form.
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
     * OIDC Core §3.1.2.6: a refusal uses the response mode a successful answer would have used, so an
     * error is posted as well, with the state and the issuer (RFC 9207 §2).
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
     * RFC 9700 §4.1: an error found before the redirect URI is validated is still shown to the user, the
     * response mode of a request that named no known client saying nothing about where to send anything.
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
     * Architecture §4.3: the mode is read once, with the redirect URI, and kept by the interaction, so a
     * request that went through the login and the consent pages is answered in the mode it asked for.
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
     * Multiple Response Type Encoding Practices §2.1: a mode the provider does not serve is refused, and
     * the refusal comes back in the default mode, the one the client is sure to read.
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
     * Decision 0006: "code" is the only response type served, in every mode, so the refusal names the
     * response type and not the mode; it is posted, the mode of the request being honoured all the same.
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
     * A valid authorization request that asks for the posted form; "oidc-demo" needs no consent, so the
     * answer comes from the authorization endpoint itself.
     *
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
     * The hidden fields of the form the page posts, in the order the response names them.
     *
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
