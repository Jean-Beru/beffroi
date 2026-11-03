<?php

declare(strict_types=1);

namespace App\Configuration;

use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * A section whose values the configuration of another bundle names, as container parameters (issue #282). They are
 * set before any extension is loaded, because an extension resolves the parameters its configuration names when it
 * is loaded itself, and Flex registers this provider after SecurityBundle, which it requires: a parameter set when this
 * provider is loaded would not exist yet for a firewall that names it.
 *
 * A parameter is printed by "debug:container --parameters", so a section exposes what may be read there and nothing
 * else: a secret is exposed as the variable of the environment it is read from, never as its value.
 */
interface ExposesParametersInterface
{
    /**
     * The parameters, by name, read from what was written under the "beffroi" key: the tree has not processed it yet,
     * so a value is as the files wrote it, an environment variable still "%env(NAME)%".
     *
     * @param list<mixed> $configs every block written under "beffroi", in the order the files were read
     *
     * @throws InvalidConfigurationException when what was written is refused
     *
     * @return array<string, string>
     */
    public function parameters(array $configs): array;
}
