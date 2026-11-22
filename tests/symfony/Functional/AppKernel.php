<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional;

use function dirname;
use function sprintf;
use App\DependencyInjection\BeffroiKernelTrait;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Kernel;
use function sys_get_temp_dir;

final class AppKernel extends Kernel
{
    use MicroKernelTrait;
    use BeffroiKernelTrait;

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load($this->getProjectDir() . '/config/config_test.yml');
        if ($this->environment !== 'test') {
            $loader->load(sprintf('%s/config/config_%s.yml', $this->getProjectDir(), $this->environment));
        }
    }

    public function getProjectDir(): string
    {
        return dirname(__DIR__);
    }

    public function getCacheDir(): string
    {
        return self::temporaryDirectory() . '/cache/' . $this->environment;
    }

    public function getLogDir(): string
    {
        return self::temporaryDirectory() . '/log';
    }

    private static function temporaryDirectory(): string
    {
        $token = getenv('TEST_TOKEN');

        return sys_get_temp_dir() . '/beffroi-integration-tests' . ($token === false || $token === '' ? '' : '-' . $token);
    }
}
