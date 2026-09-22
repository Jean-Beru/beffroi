<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use function preg_replace;
use SensitiveParameter;

/**
 * A QR code as an SVG the page embeds (architecture §5.2): drawn here, by bacon/bacon-qr-code, never by
 * a service that would be handed what it encodes, an otpauth URI carrying a secret. Squares and nothing
 * else, without the XML declaration a document embeds nowhere; the size is a hint an application styles.
 */
final readonly class QrCode
{
    /**
     * In CSS pixels, for a code an authenticator app scans off a screen at arm's length.
     */
    public const int SIZE = 240;

    public function svg(#[SensitiveParameter] string $contents): string
    {
        $svg = new Writer(new ImageRenderer(new RendererStyle(self::SIZE, 0), new SvgImageBackEnd()))->writeString($contents);

        return (string) preg_replace('/^<\?xml[^>]*\?>\s*/', '', $svg);
    }
}
