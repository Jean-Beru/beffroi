<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Bridge\Random\PlatformRandomness;
use Heidi\Oidc\Application\Secret\SecretDrawer;

/**
 * For a test that needs a value of the shape this provider draws and does not care which.
 */
final class Secrets
{
    public static function drawer(): SecretDrawer
    {
        return new SecretDrawer(new PlatformRandomness());
    }

    public static function draw(): string
    {
        return self::drawer()->draw();
    }
}
