<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Application\Token\ServedAccessTokenShapes;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;

/**
 * The shapes an access token is written in that the tests speak of, and the wirings they read them
 * from. The two names the provider writes today are written here once, so that a test says which shape
 * it is about and no test says what the provider is wired with.
 */
final readonly class Shapes
{
    public static function jwt(): AccessTokenShapeInterface
    {
        return new FakeAccessTokenIssuer('jwt');
    }

    public static function opaque(): AccessTokenShapeInterface
    {
        return new FakeAccessTokenIssuer('opaque');
    }

    /**
     * A shape nobody wrote a line of production code for.
     */
    public static function invented(): AccessTokenShapeInterface
    {
        return new FakeAccessTokenIssuer('invented');
    }

    /**
     * What the provider is wired with today: two shapes, neither of them writing anything real.
     */
    public static function served(): ServedAccessTokenShapes
    {
        return new ServedAccessTokenShapes([new FakeAccessTokenIssuer('jwt'), new FakeAccessTokenIssuer('opaque')]);
    }
}
