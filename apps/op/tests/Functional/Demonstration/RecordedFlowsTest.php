<?php

declare(strict_types=1);

namespace App\Tests\Functional\Demonstration;

use function array_column;
use PHPUnit\Framework\Attributes\Test;
use function str_contains;
use Symfony\Component\HttpFoundation\Response;

/**
 * What this provider saw of a flow, written into the trace of the demonstration as it served it (issue
 * #462). It is what makes a replay possible at all: the call that matters most of an authorization code
 * flow, the token request, is made from one server to another and no browser is in it.
 *
 * The hops here are drawn from requests this provider refuses, because what is judged is the recording
 * and not the protocol: a hop is drawn as it was sent and as it was answered, refused or not, and the
 * three suites of the monorepo judge the answers themselves.
 */
final class RecordedFlowsTest extends DemonstrationTestCase
{
    private const string CLIENT_ID = 'a-client-this-provider-never-registered';

    /**
     * RFC 6749 §3.2: the flow a call to the token endpoint belongs to is the "grant_type" it names,
     * looked up among the wired grants, and the client is the one the call names. Both halves of the
     * exchange are drawn, the request as it was sent and the answer as it came back.
     */
    #[Test]
    public function aCallToTheTokenEndpointIsDrawnOnBothHalves(): void
    {
        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::CLIENT_ID,
            'scope' => 'invoices.read',
        ]);

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
        $trace = self::traces()->of('client_credentials', self::CLIENT_ID) ?? static::fail('The call was not recorded.');
        static::assertSame(['token_request', 'token_response'], array_column($trace->hops, 'hop'));
        static::assertTrue(str_contains($trace->hops[0]->payload, 'grant_type=client_credentials'));
        static::assertSame('POST', $trace->hops[0]->method);
        static::assertSame(Response::HTTP_UNAUTHORIZED, $trace->hops[1]->status);
    }

    /**
     * A hop that failed is drawn as it failed, with the reason the provider gave for it (RFC 6749 §5.2).
     */
    #[Test]
    public function aHopThatFailedIsDrawnAsItFailed(): void
    {
        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::CLIENT_ID,
        ]);

        // Then
        $trace = self::traces()->of('client_credentials', self::CLIENT_ID) ?? static::fail('The call was not recorded.');
        static::assertTrue($trace->hops[1]->failed);
        static::assertTrue(str_contains($trace->hops[1]->payload, 'invalid_client'));
    }

    /**
     * A trace begins at the first hop of its picture: a client that plays a flow again is a run of its
     * own, and what the previous one exchanged is replaced rather than added to.
     */
    #[Test]
    public function aFlowPlayedAgainIsARunOfItsOwn(): void
    {
        // Given
        $this->askTheTokenEndpoint();
        $first = self::traces()->of('client_credentials', self::CLIENT_ID) ?? static::fail('The call was not recorded.');

        // When
        $this->askTheTokenEndpoint();

        // Then
        $second = self::traces()->of('client_credentials', self::CLIENT_ID) ?? static::fail('The call was not recorded.');
        static::assertSame(['token_request', 'token_response'], array_column($second->hops, 'hop'));
        static::assertNotSame($first->startedAt->format('U.u'), $second->startedAt->format('U.u'));
    }

    /**
     * A name the provider does not serve is a flow of no picture, and a hop of no trace: nothing is
     * recorded against a grant type nobody is wired for.
     */
    #[Test]
    public function aGrantTypeTheProviderDoesNotServeIsRecordedNowhere(): void
    {
        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'password',
            'client_id' => self::CLIENT_ID,
        ]);

        // Then
        static::assertNull(self::traces()->of('password', self::CLIENT_ID));
    }

    /**
     * Nothing of a page that is not an endpoint of this provider reaches the trace: the demonstration
     * draws the flows of the provider and not the pages of the application that installs it.
     */
    #[Test]
    public function aPageOfTheApplicationIsRecordedNowhere(): void
    {
        // When
        $this->browser->request('GET', '/account/profile');

        // Then
        static::assertSame([], self::traces()->clientsOf('authorization_code'));
    }

    /**
     * The authorization request a browser brings is drawn where it was brought, and the answer that
     * sends it to a login is this provider still working on that request: a hop of the picture is the
     * answer carried to the client, and this is not it.
     */
    #[Test]
    public function anAnswerThatKeepsTheBrowserHereIsNotTheAuthorizationResponse(): void
    {
        // When
        $this->browser->request(
            'GET',
            '/authorize?response_type=code&client_id='
            . self::CLIENT_ID
            . '&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&scope=openid&code_challenge=0123456789012345678901234567890123456789012&code_challenge_method=S256',
        );

        // Then
        $trace = self::traces()->of('authorization_code', self::CLIENT_ID) ?? static::fail('The request was not recorded.');
        static::assertSame(['authorization_request'], array_column($trace->hops, 'hop'));
        static::assertTrue(str_contains($trace->hops[0]->payload, 'response_type=code'));
    }

    private function askTheTokenEndpoint(): void
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::CLIENT_ID,
        ]);
    }
}
