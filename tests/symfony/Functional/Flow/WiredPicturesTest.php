<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Flow;

use function array_map;
use Beffroi\Bundle\Tests\Functional\Controller\BrowserTestCase;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\FlowPicturesInterface;
use PHPUnit\Framework\Attributes\Test;

/**
 * Issue #462: the flows this provider draws are the grants it is wired with. The document announces what
 * is wired (OIDC Discovery §3) and the pictures are read from the same wiring, so the two cannot
 * disagree: a grant added is announced and drawn, a grant unwired is neither.
 */
final class WiredPicturesTest extends BrowserTestCase
{
    #[Test]
    public function theFlowsDrawnAreTheGrantsTheDocumentAnnounces(): void
    {
        // Given
        $pictures = self::service('test.beffroi.flow_pictures', FlowPicturesInterface::class);

        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $announced = self::json($this->browser->getResponse())['grant_types_supported'] ?? null;
        static::assertSame($announced, array_map(
            static fn (FlowPicture $picture): string => $picture->grantType->value,
            $pictures->pictures(),
        ));
    }

    /**
     * RFC 6749 §3.2: whatever brought a flow there, it ends at the token endpoint, so every picture
     * draws that request and its answer.
     */
    #[Test]
    public function everyFlowIsDrawnAskingTheTokenEndpoint(): void
    {
        // Given
        $pictures = self::service('test.beffroi.flow_pictures', FlowPicturesInterface::class);

        // When
        $drawn = $pictures->pictures();

        // Then
        foreach ($drawn as $picture) {
            static::assertTrue(
                $picture->draws(TokenEndpointHops::REQUEST) && $picture->draws(TokenEndpointHops::RESPONSE),
                $picture->grantType->value,
            );
        }
    }
}
