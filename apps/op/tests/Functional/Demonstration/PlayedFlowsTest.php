<?php

declare(strict_types=1);

namespace App\Tests\Functional\Demonstration;

use App\Demonstration\Trace\FlowTrace;
use App\Demonstration\Trace\ProviderSideRecorder;
use function array_column;
use function base64_encode;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function json_encode;
use PHPUnit\Framework\Attributes\Test;
use function rtrim;
use function str_contains;
use function strtr;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * A flow played hop by hop from a page (issue #462): every advance takes the next hop the demonstration
 * takes itself, and both halves of it are written into the trace, the request as it was sent and the
 * answer as it came back.
 *
 * The suite has no provider at the other end of a hop, so the client the demonstration calls with is
 * one this test hands the answers of (config/services_test.yaml). What is judged is the request the
 * demonstration built and what it made of the answer.
 */
final class PlayedFlowsTest extends DemonstrationTestCase
{
    private const string FLOW = 'client_credentials';

    private const string CLIENT_ID = 'demo-service';

    /**
     * RFC 6749 §4.4.2: the client asks the token endpoint for itself. The hop drawn is the request that
     * was sent, down to the fields it carried, and the hop after it is the answer as it came back.
     */
    #[Test]
    public function anAdvanceTakesTheHopThePicturePlansAndDrawsBothHalves(): void
    {
        // Given
        $answers = $this->answering([self::tokenResponse()]);

        // When
        $this->advance();

        // Then
        $hops = $this->trace()->hops;
        static::assertSame(['token_request', 'token_response'], array_column($hops, 'hop'));
        static::assertSame('POST', $hops[0]->method);
        static::assertTrue(str_contains($hops[0]->payload, 'grant_type=client_credentials'));
        static::assertTrue(str_contains($hops[0]->payload, 'scope=invoices.read'));
        static::assertSame(Response::HTTP_OK, $hops[1]->status);
        static::assertSame('https://op.test/token', $answers[0]->getRequestUrl());
    }

    /**
     * The call carries the user agent of the demonstration, which is how the recorder of the provider's
     * side knows to leave that hop to the demonstration rather than record it a second time.
     */
    #[Test]
    public function theCallSaysItIsTheDemonstrationsOwn(): void
    {
        // Given
        $answers = $this->answering([self::tokenResponse()]);

        // When
        $this->advance();

        // Then
        $headers = $answers[0]->getRequestOptions()['headers'] ?? [];
        static::assertIsArray($headers);
        static::assertContains('User-Agent: ' . ProviderSideRecorder::AGENT, $headers);
    }

    /**
     * RFC 6749 §2.3.1: a client that holds a secret authenticates with it, and that header is not
     * drawn. A picture of a flow is not a place to read a secret from.
     */
    #[Test]
    public function theSecretTheClientAuthenticatesWithIsNotDrawn(): void
    {
        // Given
        $this->answering([self::tokenResponse()]);

        // When
        $this->advance();

        // Then
        static::assertFalse(str_contains($this->trace()->hops[0]->payload, 'client_id='));
        static::assertFalse(str_contains($this->trace()->hops[0]->payload, 'secret'));
    }

    /**
     * RFC 7515 §3.1: a compact JWT of an answer is drawn raw and decoded, header and claims, under the
     * name the payload gave it. Nothing is verified: what the page shows is a reading.
     */
    #[Test]
    public function aCompactJwtOfTheAnswerIsDrawnRawAndDecoded(): void
    {
        // Given
        $this->answering([self::tokenResponse()]);

        // When
        $drawing = $this->advance();

        // Then
        $jwts = self::jwtsOf($drawing, 1);
        static::assertArrayHasKey('access_token', $jwts);
        static::assertTrue(str_contains($jwts['access_token']['header'], '"at+jwt"'));
        static::assertTrue(str_contains((string) $jwts['access_token']['claims'], '"demo-service"'));
    }

    /**
     * RFC 6749 §5.2: a hop that failed is drawn as it failed, with the reason the provider gave.
     */
    #[Test]
    public function aHopThatFailedIsDrawnAsItFailed(): void
    {
        // Given
        $this->answering([new MockResponse(
            json_encode([
                'error' => 'invalid_scope',
                'error_description' => 'The client asked for a scope it does not hold.',
            ], JSON_THROW_ON_ERROR),
            ['http_code' => Response::HTTP_BAD_REQUEST],
        )]);

        // When
        $this->advance();

        // Then
        $answer = $this->trace()->hops[1];
        static::assertTrue($answer->failed);
        static::assertSame('invalid_scope: The client asked for a scope it does not hold.', $answer->reason);
    }

    /**
     * A hop the client of the run does not hold what it needs for is said to be, and nothing is sent:
     * a token that never came back is a token nothing can be introspected with.
     */
    #[Test]
    public function aHopTheClientHoldsNothingForIsDrawnAsNotTaken(): void
    {
        // Given
        $this->answering([new MockResponse(
            json_encode(['token_type' => 'Bearer'], JSON_THROW_ON_ERROR),
            ['http_code' => Response::HTTP_OK],
        )]);
        $this->advance();

        // When
        $this->advance();

        // Then
        $unheld = $this->trace()->hops[2];
        static::assertSame('introspection_response', $unheld->hop);
        static::assertTrue($unheld->failed);
        static::assertSame('', $unheld->payload);
    }

    /**
     * A run started over forgets what the previous one exchanged, which is the only way a flow played
     * twice is not read as one flow played oddly.
     */
    #[Test]
    public function aRunStartedOverForgetsWhatThePreviousOneExchanged(): void
    {
        // Given
        $this->answering([self::tokenResponse()]);
        $this->advance();

        // When
        $this->browser->request('POST', '/demonstration/flow/open?flow=' . self::FLOW);

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], $this->trace()->hops);
    }

    /**
     * @param list<MockResponse> $answers
     *
     * @return list<MockResponse> the same ones, which hold the request they were handed
     */
    private function answering(array $answers): array
    {
        self::service('test.app.demonstration_http_client', MockHttpClient::class)->setResponseFactory($answers);

        return $answers;
    }

    /**
     * @return array<array-key, mixed> the drawing the advance answered
     */
    private function advance(): array
    {
        $this->browser->request('POST', '/demonstration/flow/advance?flow=' . self::FLOW);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $drawing = json_decode(self::string($response->getContent()), true);
        static::assertIsArray($drawing);

        return $drawing;
    }

    private function trace(): FlowTrace
    {
        return self::traces()->of(self::FLOW, self::CLIENT_ID) ?? static::fail('The run left no trace.');
    }

    /**
     * The compact JWTs the drawing holds for one of its hops, by the name the payload gave them.
     *
     * @param array<array-key, mixed> $drawing
     *
     * @return array<string, array{header: string, claims: string|null}>
     */
    private static function jwtsOf(array $drawing, int $index): array
    {
        $hops = $drawing['hops'] ?? null;
        static::assertIsArray($hops);
        $hop = $hops[$index] ?? null;
        static::assertIsArray($hop);
        $jwts = $hop['jwts'] ?? null;
        static::assertIsArray($jwts);

        $read = [];
        foreach ($jwts as $jwt) {
            static::assertIsArray($jwt);
            $name = $jwt['name'] ?? null;
            $header = $jwt['header'] ?? null;
            $claims = $jwt['claims'] ?? null;
            static::assertIsString($name);
            static::assertIsString($header);
            static::assertTrue($claims === null || is_string($claims));
            $read[$name] = [
                'header' => $header,
                'claims' => is_string($claims) ? $claims : null,
            ];
        }

        return $read;
    }

    /**
     * An answer of the token endpoint carrying an "at+jwt" (RFC 9068 §2.1), as this provider answers a
     * client that asks for itself.
     */
    private static function tokenResponse(): MockResponse
    {
        return new MockResponse(
            json_encode([
                'access_token' => self::compactJwt(
                    ['typ' => 'at+jwt', 'alg' => 'RS256'],
                    ['iss' => 'https://op.test', 'sub' => self::CLIENT_ID, 'client_id' => self::CLIENT_ID, 'scope' => 'invoices.read'],
                ),
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'scope' => 'invoices.read',
            ], JSON_THROW_ON_ERROR),
            ['http_code' => Response::HTTP_OK],
        );
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    private static function compactJwt(array $header, array $claims): string
    {
        return (
            self::base64url(json_encode($header, JSON_THROW_ON_ERROR))
            . '.'
            . self::base64url(json_encode($claims, JSON_THROW_ON_ERROR))
            . '.'
            . self::base64url('not a signature')
        );
    }

    private static function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
