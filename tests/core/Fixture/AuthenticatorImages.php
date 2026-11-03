<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

/**
 * Logos of models of authenticator for the tests, in the data: URLs the sources write them in: a PNG, as the
 * FIDO metadata carry one, and an SVG for a light page and one for a dark page, as the list of the community does.
 */
final class AuthenticatorImages
{
    /**
     * One transparent pixel.
     */
    public const string PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

    /**
     * A black square.
     */
    public const string SVG_LIGHT = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxIDEiPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiIGZpbGw9IiMwMDAiLz48L3N2Zz4=';

    /**
     * A white square.
     */
    public const string SVG_DARK = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxIDEiPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiIGZpbGw9IiNmZmYiLz48L3N2Zz4=';
}
