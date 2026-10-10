<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional;

use function dirname;
use function sprintf;
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

    /**
     * The configuration of the suite, and the one file an environment of its own adds to it: a rule that
     * holds on what a container does and not on what a YAML file says is judged by building the two
     * containers, so a test boots this kernel in a second environment and gets config_test.yml followed by
     * the file named after that environment (config_<environment>.yml, issue #196). Each environment
     * compiles its own container, into the cache directory named after it.
     */
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

    /**
     * Everything a run of the suite writes outside the repository, and everything configured under it: the
     * compiled container, the SQLite file of "beffroi_test.database", the sealed keys of "%kernel.cache_dir%
     * /keys" and the metadata of "%kernel.cache_dir%/webauthn".
     *
     * A parallel runner gives each of its workers a TEST_TOKEN, and that token is what makes this directory
     * the worker's own, so one compiled container and one database per process instead of one for all of
     * them. One process and no token is the directory it has always been, which is what a developer running
     * a single test gets.
     */
    private static function temporaryDirectory(): string
    {
        $token = getenv('TEST_TOKEN');

        return sys_get_temp_dir() . '/beffroi-bundle-tests' . ($token === false || $token === '' ? '' : '-' . $token);
    }
}
