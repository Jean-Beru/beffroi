<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional;

use function dirname;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Kernel;
use function sys_get_temp_dir;

/**
 * Bundles are listed in tests/symfony/config/bundles.php, read by the kernel from the project directory.
 */
final class AppKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load($this->getProjectDir() . '/config/config_test.yml');
    }

    public function getProjectDir(): string
    {
        return dirname(__DIR__);
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/beffroi-bundle-tests/cache/' . $this->environment;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/beffroi-bundle-tests/log';
    }
}
