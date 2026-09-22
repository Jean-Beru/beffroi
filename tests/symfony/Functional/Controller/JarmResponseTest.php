<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function array_keys;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Tests\Fixture\Algorithms;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * JWT Secured Authorization Response Mode §2.1 and §2.4, issue #163: a client that asks for a signed
 * answer gets one document, signed by the active key of its tenant, whichever way it is delivered; a
 * refusal is signed the same way, and "state" travels inside the document and nowhere else.
 */
final class JarmResponseTest extends BrowserTestCase
{
    private const string CLIENT = 'jarm-app';

    private const string REDIRECT_URI = 'https://jarm.test/callback';

    /**
     * JARM §2.1: "jwt" names the signed mode the "code" response type defaults to, "query.jwt", so the
     * document travels in the query as "response" and nothing else does.
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
     * JARM §2.1: the parameters of the response are the claims of the document, "state" among them, with
     * the issuer, the audience naming the client and an expiry.
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
     * JARM §2.1: the client reads its answer in the document, so nothing of it is written beside it.
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
     * JARM §2.4: a client that asked for a signed answer never gets an unsigned refusal; the error and
     * the state are claims of the same document.
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
     * RFC 9700 §4.1: a failure of the first stage is not redirected at all, signed or not, the request
     * having said nothing trustworthy about where to send anything.
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
     * JARM §2.1: "form_post.jwt" posts the very same document by the page of Form Post Response Mode §2,
     * which is one hidden field and no more.
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
     * Architecture §3.3: the key that signed a document stays published while the document can be
     * verified, so a rotation between the answer and the moment the client reads it breaks nothing.
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

    /**
     * A client that asks for nothing keeps the default mode, unchanged: the parameters in the query.
     */
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
     * The key the answers of "jarm-app" are signed with: it registered ES256, so the tenant needs an
     * active key of that algorithm (JARM §3). Called again, it is a rotation.
     */
    private static function signedResponseKey(): SigningKey
    {
        return self::rotator()
            ->rotate(self::tenant(), Algorithms::es256(), self::context());
    }

    /**
     * A valid authorization request of "jarm-app" asking for a signed answer; "jarm-app" needs no
     * consent, so the answer comes from the authorization endpoint itself.
     *
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    private static function jarmParameters(array $parameters = []): array
    {
        return self::authorizationParameters(self::CLIENT, $parameters + [
            'redirect_uri' => self::REDIRECT_URI,
            'response_mode' => 'jwt',
        ]);
    }

    /**
     * The one parameter a signed answer carries (JARM §2.1).
     */
    private static function document(Response $response): string
    {
        return self::redirectedQuery($response)['response'] ?? static::fail('The redirection carries no signed response.');
    }

    /**
     * The signature against the JWK Set the provider publishes, which is what the client verifies it
     * with, then the header and the claims.
     *
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     */
    private function verified(string $document): array
    {
        $this->browser->request('GET', '/jwks');
        $jws = new CompactSerializer()
            ->unserialize($document);
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
            'header' => $jws->getSignature(0)
                ->getProtectedHeader(),
            'claims' => $claims,
        ];
    }

    /**
     * The hidden fields of the form the page posts.
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
