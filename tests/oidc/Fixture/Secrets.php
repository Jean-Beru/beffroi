<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Oidc\Application\Secret\SecretDrawer;

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
