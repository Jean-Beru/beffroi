<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Token\ServedAccessTokenShapes;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;

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

    public static function invented(): AccessTokenShapeInterface
    {
        return new FakeAccessTokenIssuer('invented');
    }

    public static function served(): ServedAccessTokenShapes
    {
        return new ServedAccessTokenShapes([new FakeAccessTokenIssuer('jwt'), new FakeAccessTokenIssuer('opaque')]);
    }
}
