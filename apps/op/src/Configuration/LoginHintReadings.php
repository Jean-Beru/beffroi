<?php

declare(strict_types=1);

namespace App\Configuration;

use function array_keys;
use function array_map;
use Beffroi\Oidc\Application\Hint\SubjectLoginHint;
use Beffroi\Oidc\Application\Hint\UsernameLoginHint;
use Beffroi\Oidc\Application\Hint\UserHintInterface;
use Generator;
use function implode;
use function in_array;
use IteratorAggregate;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Loader\Configurator\InlineServiceConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_locator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;
use Symfony\Contracts\Service\ServiceProviderInterface;

/**
 * The readings of a "login_hint" one side of the provider is wired with: those a deployment tags, then the one of the
 * provider the configuration names for that side. The provider ships its readings under one list of names and not two:
 * the authorization request a browser carries (OIDC Core §3.1.2.1) and the backchannel authentication request a client
 * makes (CIBA Core §7.1) carry the same parameter, so a deployment names the same readings on both sides rather than
 * learning a vocabulary per side.
 *
 * The name may be a value of the environment, one only once the container runs (decision 0030): it is held to the
 * names the tree accepts when the container builds the list, and the reading it names is built only then. A
 * deployment whose clients name their users some other way tags a UserHintInterface of its own and says "none"; two
 * things reading one parameter is a wiring with two answers, and is refused where the hint is read rather than
 * allowed to pick one.
 *
 * @implements IteratorAggregate<int, UserHintInterface>
 */
final readonly class LoginHintReadings implements IteratorAggregate
{
    /**
     * CIBA Core §15: the subject, which says who somebody is to this provider and to this client, and
     * nowhere else.
     */
    public const string DEFAULT = 'sub';

    /**
     * What a deployment that tags a reading of its own says, there being nothing of the provider to read.
     */
    private const string NONE = 'none';

    /**
     * @var array<string, class-string<UserHintInterface>>
     */
    private const array READINGS = [
        'sub' => SubjectLoginHint::class,
        'username' => UsernameLoginHint::class,
    ];

    /**
     * @param iterable<UserHintInterface> $tagged the readings the deployment tagged for that side
     * @param string $name the reading of the provider the configuration names, or "none"
     * @param ServiceProviderInterface<UserHintInterface> $readings the readings of the provider, by their name
     * @param string $key the node the name was written under, which the refusal names
     *
     * @throws InvalidConfigurationException when the name is none the tree accepts
     */
    public function __construct(
        private iterable $tagged,
        private string $name,
        private ServiceProviderInterface $readings,
        string $key,
    ) {
        if (! in_array($name, self::names(), true)) {
            throw new InvalidConfigurationException(sprintf(
                'The "beffroi" configuration key "%s" names one of %s, "%s" given.',
                $key,
                implode(', ', array_map(static fn (string $known): string => '"' . $known . '"', self::names())),
                $name,
            ));
        }
    }

    /**
     * @return list<string>
     */
    public static function names(): array
    {
        return [...array_keys(self::READINGS), self::NONE];
    }

    /**
     * The readings of that side as the container builds them, for the service that reads them: those tagged, then the
     * one the configuration names.
     *
     * @param string $name the name, or the environment placeholder that stands for it until runtime
     */
    public static function wired(string $tag, string $name, string $key): InlineServiceConfigurator
    {
        return inline_service(self::class)->args([
            tagged_iterator($tag),
            $name,
            service_locator(array_map(service(...), self::READINGS)),
            $key,
        ]);
    }

    /**
     * @return Generator<int, UserHintInterface>
     */
    public function getIterator(): Generator
    {
        foreach ($this->tagged as $reading) {
            yield $reading;
        }
        if ($this->name === self::NONE) {
            return;
        }
        yield $this->readings->get($this->name);
    }
}
