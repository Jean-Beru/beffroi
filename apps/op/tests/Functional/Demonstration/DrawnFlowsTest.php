<?php

declare(strict_types=1);

namespace App\Tests\Functional\Demonstration;

use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Port\FlowPicturesInterface;
use PHPUnit\Framework\Attributes\Test;
use function is_string;
use function json_decode;
use function parse_str;
use function parse_url;
use const PHP_URL_QUERY;
use function sprintf;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The pages where the demonstration draws the flows this provider serves (issue #462), on the kernel this
 * application deploys: they are routed in development and in this suite, and in a deployment they are
 * not there at all.
 *
 * What is judged here is that the set of pages is the wiring. The shapes themselves are judged by the
 * suite of the module, on fake wirings of grants.
 */
final class DrawnFlowsTest extends DemonstrationTestCase
{
    /**
     * A name no grant of this provider gives itself: decision 0006 wired no password grant and never
     * will.
     */
    private const string UNSERVED_GRANT = 'password';

    /**
     * OIDC Discovery §3: the document announces what is wired, the pictures are read from the same
     * wiring, and the index draws those grants in that order. Unwiring a grant takes its picture off
     * this page without a line being edited.
     */
    #[Test]
    public function theIndexDrawsTheGrantsTheDocumentAnnounces(): void
    {
        // Given
        $announced = $this->announcedGrantTypes();

        // When
        $index = $this->browser->request('GET', '/demonstration/');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame($announced, $this->drawnGrantTypes($index));
    }

    #[Test]
    public function thePicturesAreTheGrantsTheDocumentAnnounces(): void
    {
        // Given
        $pictures = self::service('test.beffroi.flow_pictures', FlowPicturesInterface::class);

        // When
        $announced = $this->announcedGrantTypes();

        // Then
        static::assertSame($announced, array_map(
            static fn (FlowPicture $picture): string => $picture->grantType->value,
            $pictures->pictures(),
        ));
    }

    #[Test]
    public function aFlowThisProviderDoesNotServeHasNoPage(): void
    {
        // When
        $this->browser->request('GET', sprintf('/demonstration/flow?flow=%s', self::UNSERVED_GRANT));

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aPageAskedForNoFlowAtAllIsNoPage(): void
    {
        // When
        $this->browser->request('GET', '/demonstration/flow');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 6749 §4.1: the page of a flow carries the hops its picture plans, in the order the flow
     * happens in, each with the section of the specification that says what it is.
     */
    #[Test]
    public function thePageOfAFlowCarriesTheHopsItsPicturePlans(): void
    {
        // When
        $page = $this->browser->request('GET', '/demonstration/flow?flow=authorization_code');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            [
                'authorization_request',
                'authorization_response',
                'token_request',
                'token_response',
                'userinfo_request',
                'userinfo_response',
                'introspection_request',
                'introspection_response',
                'refresh_request',
                'refresh_response',
                'revocation_request',
                'revocation_response',
            ],
            $page->filter('ol.plan li')->each(static fn (Crawler $hop): string => (string) $hop->attr('data-hop')),
        );
    }

    /**
     * A flow nothing has played yet is drawn with its plan and with nothing in it: a picture is not a
     * payload, and the page of a flow nobody has run shows none.
     */
    #[Test]
    public function aFlowNothingHasPlayedIsDrawnWithAnEmptyTrace(): void
    {
        // When
        $page = $this->browser->request('GET', '/demonstration/flow?flow=authorization_code');

        // Then
        static::assertSame('[]', $page->filter('#flow')->attr('data-trace'));
        static::assertSame([], $page->filter('ol.plan li[data-taken]')->each(static fn (Crawler $hop): string => (string) $hop->attr('data-hop')));
    }

    /**
     * The flows the demonstration drives itself are the ones the lab registered a client for
     * (config/packages/demonstration.yaml): a flow that opens in a browser navigating away is replayed, and the page
     * says which of the two it is.
     */
    #[Test]
    public function aFlowTheLabHasNoClientForIsNotPlayedFromThePage(): void
    {
        // When
        $this->browser->request('POST', '/demonstration/flow/advance?flow=authorization_code');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CONFLICT, $response->getStatusCode());
        static::assertStringContainsString('no client for this flow', self::string($response->getContent()));
    }

    /**
     * @return list<string>
     */
    private function announcedGrantTypes(): array
    {
        $this->browser->request('GET', '/.well-known/openid-configuration');
        $document = json_decode(self::string($this->browser->getResponse()->getContent()), true);
        static::assertIsArray($document);
        $announced = $document['grant_types_supported'] ?? null;
        static::assertIsArray($announced);

        $grantTypes = [];
        foreach ($announced as $grantType) {
            static::assertIsString($grantType);
            $grantTypes[] = $grantType;
        }

        return $grantTypes;
    }

    /**
     * @return list<string>
     */
    private function drawnGrantTypes(Crawler $index): array
    {
        return $index
            ->filter('section.card h2 a')
            ->each(static function (Crawler $link): string {
                $query = parse_url((string) $link->attr('href'), PHP_URL_QUERY);
                parse_str(is_string($query) ? $query : '', $parameters);
                $flow = $parameters['flow'] ?? null;

                return is_string($flow) ? $flow : '';
            });
    }
}
