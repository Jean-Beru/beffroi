<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_keys;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * JWT Secured Authorization Response Mode §2.1, §2.4
 */
final class JarmResponseTest extends BrowserTestCase
{
    private const string CLIENT = 'jarm-app';

    private const string REDIRECT_URI = 'https://jarm.test/callback';

    /**
     * JARM §2.1
     */
    #[Test]
    public function theAnswerIsOneSignedDocumentInTheQuery(): void
    {
        // Given
        self::signedResponseKey();
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::jarmParameters());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame(['response'], array_keys(self::redirectedQuery($response)));
    }

    /**
     * JARM §2.1
     */
    #[Test]
    public function theDocumentCarriesTheCodeTheStateAndTheIssuer(): void
    {
        // Given
        $key = self::signedResponseKey();
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::jarmParameters());

        // Then
        ['header' => $header, 'claims' => $claims] = $this->verified(self::document($this->browser->getResponse()));
        static::assertSame('ES256', $header['alg']);
        static::assertSame($key->kid, $header['kid']);
        static::assertArrayHasKey('code', $claims);
        static::assertSame('state-of-the-client', $claims['state']);
        static::assertSame('https://op.test', $claims['iss']);
        static::assertSame(self::CLIENT, $claims['aud']);
        static::assertGreaterThan(self::currentSecond()->getTimestamp(), $claims['exp']);
    }

    /**
     * JARM §2.1
     */
    #[Test]
    public function neitherTheStateNorTheCodeIsWrittenBesideTheDocument(): void
    {
        // Given
        self::signedResponseKey();
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::jarmParameters());

        // Then
        $query = self::redirectedQuery($this->browser->getResponse());
        static::assertArrayNotHasKey('state', $query);
        static::assertArrayNotHasKey('code', $query);
        static::assertArrayNotHasKey('iss', $query);
    }

    /**
     * JARM §2.4
     */
    #[Test]
    public function aRefusalIsASignedDocumentToo(): void
    {
        // Given
        self::signedResponseKey();

        // When
        $this->browser->request('GET', '/authorize', self::jarmParameters([
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]));

        // Then
        ['claims' => $claims] = $this->verified(self::document($this->browser->getResponse()));
        static::assertSame('invalid_request', $claims['error']);
        static::assertSame('The code_challenge parameter is missing (RFC 7636 section 4.3).', $claims['error_description']);
        static::assertSame('state-of-the-client', $claims['state']);
    }

    /**
     * RFC 9700 §4.1
     */
    #[Test]
    public function anErrorOfTheFirstStageIsStillAPage(): void
    {
        // Given
        self::signedResponseKey();

        // When
        $this->browser->request('GET', '/authorize', self::jarmParameters([
            'redirect_uri' => 'https://jarm.test/elsewhere',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * JARM §2.1, Form Post Response Mode §2
     */
    #[Test]
    public function theSignedFormPostDeliversTheSameDocumentInAPage(): void
    {
        // Given
        self::signedResponseKey();
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/authorize', self::jarmParameters([
            'response_mode' => 'form_post.jwt',
        ]));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::REDIRECT_URI, $crawler->filter('form')->attr('action'));
        $posted = self::postedFields($crawler);
        static::assertSame(['response'], array_keys($posted));
        ['claims' => $claims] = $this->verified($posted['response']);
        static::assertArrayHasKey('code', $claims);
    }

    /**
     * Architecture §3.3
     */
    #[Test]
    public function aRotationDuringTheFlowDoesNotBreakTheDocument(): void
    {
        // Given
        $key = self::signedResponseKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::jarmParameters());
        $document = self::document($this->browser->getResponse());

        // When
        self::signedResponseKey();

        // Then
        ['header' => $header] = $this->verified($document);
        static::assertSame($key->kid, $header['kid']);
    }

    #[Test]
    public function aClientThatAsksForNothingKeepsTheQuery(): void
    {
        // Given
        self::signedResponseKey();
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::jarmParameters([
            'response_mode' => null,
        ]));

        // Then
        $query = self::redirectedQuery($this->browser->getResponse());
        static::assertArrayHasKey('code', $query);
        static::assertArrayNotHasKey('response', $query);
    }

    /**
     * An ES256 key, the algorithm "jarm-app" registered (JARM §3); called again, it is a rotation.
     */
    private static function signedResponseKey(): TenantKey
    {
        return self::takeOver()->rotate(self::tenant(), Algorithms::es256(), self::context());
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    private static function jarmParameters(array $parameters = []): array
    {
        return self::authorizationParameters(
            self::CLIENT,
            $parameters
            + [
                'redirect_uri' => self::REDIRECT_URI,
                'response_mode' => 'jwt',
            ],
        );
    }

    /**
     * JARM §2.1
     */
    private static function document(Response $response): string
    {
        return self::redirectedQuery($response)['response'] ?? static::fail('The redirection carries no signed response.');
    }

    /**
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     */
    private function verified(string $document): array
    {
        $this->browser->request('GET', '/jwks');
        $jws = new CompactSerializer()->unserialize($document);
        static::assertTrue(
            new JWSVerifier(Algorithms::all()->manager())->verifyWithKeySet($jws, JWKSet::createFromKeyData(self::json($this->browser->getResponse())), 0),
            'the signature verifies against the published JWK Set',
        );
        $decoded = json_decode((string) $jws->getPayload(), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($decoded);
        $claims = [];
        foreach ($decoded as $name => $value) {
            $claims[(string) $name] = $value;
        }

        return [
            'header' => $jws->getSignature(0)->getProtectedHeader(),
            'claims' => $claims,
        ];
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
