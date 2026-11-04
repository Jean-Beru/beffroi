<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Flow;

use function array_map;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\FlowPicturesInterface;
use PHPUnit\Framework\Attributes\Test;

/**
 * OIDC Discovery §3
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
     * RFC 6749 §3.2
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
