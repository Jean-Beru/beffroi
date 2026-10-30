<?php

declare(strict_types=1);

namespace App\Tests\Image;

use const ARRAY_FILTER_USE_KEY;
use function array_filter;
use function array_keys;
use function array_map;
use function array_pop;
use function array_unique;
use function array_values;
use function count;
use function dirname;
use function explode;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function preg_match;
use function preg_match_all;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use function sort;
use function str_starts_with;
use function strlen;
use function strpbrk;
use function substr;
use Symfony\Component\Yaml\Yaml;

/**
 * A YAML file of the configuration of this application, read the way its kernel reads it (issue #922): Symfony
 * reads the configuration of an environment in that environment alone, from where it looks for it
 * (KernelTrait::configureContainer() and MicroKernelTrait::configureRoutes(), 8.2: config/packages/<env>/,
 * config/routes/<env>/, config/services_<env>.yaml) and from the sections "when@<env>" of any other file (the
 * YamlFileLoader of DependencyInjection and of Routing). An environment is another one when it is not "prod", the
 * one the image runs in (APP_ENV of apps/op/Dockerfile).
 */
final readonly class ConfigurationFile
{
    private const string PRODUCTION = 'prod';

    private const string PROJECT_DIRECTORY = '%kernel.project_dir%/';

    /**
     * @param string $file the path of the file in the application
     * @param array<mixed> $content
     */
    private function __construct(
        public string $file,
        private array $content,
    ) {
    }

    /**
     * @return list<self> every YAML file of config/, in the order of their paths
     */
    public static function everyOne(): array
    {
        $directory = ApplicationFiles::path('config');
        $files = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)) as $entry) {
            if ($entry instanceof SplFileInfo && in_array($entry->getExtension(), ['yaml', 'yml'], true)) {
                $files[] = 'config/' . substr($entry->getPathname(), strlen($directory) + 1);
            }
        }
        sort($files);

        return array_map(self::of(...), $files);
    }

    /**
     * @param string $file the path of the file in the application
     */
    public static function of(string $file): self
    {
        $content = Yaml::parseFile(ApplicationFiles::path($file), Yaml::PARSE_CONSTANT | Yaml::PARSE_CUSTOM_TAGS);

        return new self($file, is_array($content) ? $content : []);
    }

    /**
     * @return list<string> the environments other than production its sections "when@<env>" configure
     */
    public function otherEnvironments(): array
    {
        $environments = [];
        foreach (array_keys($this->content) as $key) {
            if (is_string($key) && $this->isASectionOfAnotherEnvironment($key)) {
                $environments[] = substr($key, strlen('when@'));
            }
        }

        return $environments;
    }

    /**
     * Whether it is read in other environments than production alone: where Symfony looks for the configuration of
     * one, or every section of it being one of theirs.
     */
    public function isOfAnotherEnvironment(): bool
    {
        if (preg_match('#^config/(?:packages|routes)/([^/]+)/#', $this->file, $directory) === 1) {
            return $directory[1] !== self::PRODUCTION;
        }
        if (preg_match('#^config/services_([^/]+)\.ya?ml$#D', $this->file, $services) === 1) {
            return $services[1] !== self::PRODUCTION;
        }

        return $this->content !== [] && count($this->otherEnvironments()) === count($this->content);
    }

    /**
     * @return list<string> the variables of the environment a production kernel reads in it, by the placeholders
     *                      "%env(...)%" of its values and the defaults "env(NAME)" of its parameters: none in a file
     *                      of another environment, and none in its sections "when@<env>" of another one
     */
    public function variablesReadInProduction(): array
    {
        if ($this->isOfAnotherEnvironment()) {
            return [];
        }

        return self::variablesIn(array_filter($this->content, fn (mixed $key): bool => ! $this->isASectionOfAnotherEnvironment($key), ARRAY_FILTER_USE_KEY));
    }

    /**
     * @return list<string> the variables of the environment it reads in another environment than production alone
     */
    public function variablesReadElsewhere(): array
    {
        if ($this->isOfAnotherEnvironment()) {
            return self::variablesIn($this->content);
        }

        return self::variablesIn(array_filter($this->content, $this->isASectionOfAnotherEnvironment(...), ARRAY_FILTER_USE_KEY));
    }

    /**
     * @return list<string> the paths of the application it names, each by its path in the application: what the
     *                      kernel loads a resource from, the classes of a prototype of services or a file of the
     *                      container or of routes it imports, read from the directory of the file; and any path under
     *                      the directory of the project, "%kernel.project_dir%"
     */
    public function namedPaths(): array
    {
        $paths = array_filter(
            array_map(self::inTheApplication(...), [...$this->loadedResources(), ...self::underTheProject($this->content)]),
            static fn (?string $path): bool => $path !== null,
        );

        return array_values(array_unique($paths));
    }

    /**
     * What YamlFileLoader loads a resource from: an entry of "imports" or of "services" in a file of the container,
     * an entry of a file of routes, each in the file itself or in one of its sections "when@<env>".
     *
     * @return list<string>
     */
    private function loadedResources(): array
    {
        $routes = $this->file === 'config/routes.yaml' || str_starts_with($this->file, 'config/routes/');
        $resources = [];
        foreach (self::sectionsOf($this->content) as $section) {
            $entries = $routes ? $section : [...self::listOf($section['imports'] ?? []), ...self::listOf($section['services'] ?? [])];
            foreach ($entries as $entry) {
                $resource = is_array($entry) ? $entry['resource'] ?? null : $entry;
                // A service that loads routes, a bundle and a placeholder name no file read from here: the path
                // under the directory of the project is read with every other one.
                if (! is_string($resource) || is_array($entry) && ($entry['type'] ?? null) === 'service' || str_starts_with($resource, '@')) {
                    continue;
                }
                $resources[] = dirname($this->file) . '/' . $resource;
            }
        }

        return $resources;
    }

    /**
     * @param array<mixed> $content
     *
     * @return list<array<mixed>> the file outside its sections "when@<env>", then each of them
     */
    private static function sectionsOf(array $content): array
    {
        $sections = [array_filter($content, static fn (mixed $key): bool => ! is_string($key) || ! str_starts_with($key, 'when@'), ARRAY_FILTER_USE_KEY)];
        foreach ($content as $key => $section) {
            if (is_string($key) && str_starts_with($key, 'when@') && is_array($section)) {
                $sections[] = $section;
            }
        }

        return $sections;
    }

    /**
     * @return array<mixed>
     */
    private static function listOf(mixed $entries): array
    {
        return is_array($entries) ? $entries : [];
    }

    /**
     * @param array<mixed> $node
     *
     * @return list<string> every value of the node and of the nodes under it that is a path under the directory of
     *                      the project, from that directory
     */
    private static function underTheProject(array $node): array
    {
        $paths = [];
        foreach ($node as $value) {
            if (is_string($value) && str_starts_with($value, self::PROJECT_DIRECTORY)) {
                $paths[] = substr($value, strlen(self::PROJECT_DIRECTORY));
            }
            if (is_array($value)) {
                $paths = [...$paths, ...self::underTheProject($value)];
            }
        }

        return $paths;
    }

    private function isASectionOfAnotherEnvironment(mixed $key): bool
    {
        return is_string($key) && preg_match('/^when@(.+)$/D', $key, $section) === 1 && $section[1] !== self::PRODUCTION;
    }

    /**
     * @param array<mixed> $node
     *
     * @return list<string> the variables a placeholder of the node or of a node under it reads, the last name of
     *                      "%env(processor:...:NAME)%", and the ones a parameter "env(NAME)" gives a default
     */
    private static function variablesIn(array $node): array
    {
        $variables = [];
        foreach ($node as $key => $value) {
            if (is_string($key) && preg_match('/^env\((?:[^:()]*:)*([^:()]+)\)$/D', $key, $default) === 1) {
                $variables[] = $default[1];
            }
            if (is_string($value) && preg_match_all('/%env\((?:[^:()%]*:)*([^:()%]+)\)%/', $value, $placeholders) > 0) {
                $variables = [...$variables, ...$placeholders[1]];
            }
            if (is_array($value)) {
                $variables = [...$variables, ...self::variablesIn($value)];
            }
        }

        return array_values(array_unique($variables));
    }

    /**
     * The path without its "." and ".." segments, up to the first segment that is a pattern, when it stays in the
     * application, and nothing when it leaves it or names another placeholder.
     */
    private static function inTheApplication(string $path): ?string
    {
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if (str_starts_with($segment, '%')) {
                return null;
            }
            if (strpbrk($segment, '*?[{') !== false) {
                break;
            }
            if ($segment === '..') {
                if ($segments === []) {
                    return null;
                }
                array_pop($segments);

                continue;
            }
            if ($segment !== '' && $segment !== '.') {
                $segments[] = $segment;
            }
        }

        return $segments === [] ? null : implode('/', $segments);
    }
}
