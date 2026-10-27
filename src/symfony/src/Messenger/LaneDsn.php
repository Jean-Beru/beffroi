<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Messenger;

use Closure;
use function is_string;
use function sprintf;
use function str_contains;
use function str_replace;
use function strpos;
use function substr;
use Symfony\Component\DependencyInjection\EnvVarProcessorInterface;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

/**
 * The DSN of one lane, read from the one a deployment names for the four (architecture §5.6, issue #919):
 * `{lane}` is where the name of the lane goes, a queue of the table, an exchange of a broker, a stream, so
 * that each lane is a queue of its own whatever the transport, and nothing here reads a scheme.
 *
 * **A DSN that names no lane is refused** when the transport it reaches is built, rather than served. The
 * four lanes would then be one queue: the worker asks its receivers in the order it is given them and starts
 * again from the first after each message, so the receiver of the first lane named would take every message
 * and handle each on the patience of its own lane, an enrichment tried again like a logout token, or a
 * logout token like a write of our own.
 */
final readonly class LaneDsn implements EnvVarProcessorInterface
{
    public const string PREFIX = 'beffroi_lane';

    public const string PLACEHOLDER = '{lane}';

    /**
     * What the transport of a lane is given: the DSN the variable carries, the lane in place of `{lane}`.
     */
    public static function of(string $lane, string $variable): string
    {
        return '%env(' . self::PREFIX . ':' . $lane . ':' . $variable . ')%';
    }

    /**
     * @param string $name the lane, then the variable that carries the DSN, as of() writes them
     *
     * @throws RuntimeException when the name carries no lane, or the DSN names no `{lane}`; the refusal names
     *                          the variable and never its value, which carries the credentials of a broker
     */
    public function getEnv(string $prefix, string $name, Closure $getEnv): string
    {
        $separator = strpos($name, ':');
        if ($separator === false) {
            throw new RuntimeException(sprintf('Invalid env "%s:%s": the lane the DSN is read for comes first.', self::PREFIX, $name));
        }
        $variable = substr($name, $separator + 1);
        $dsn = $getEnv($variable);
        if (! is_string($dsn) || ! str_contains($dsn, self::PLACEHOLDER)) {
            throw new RuntimeException(sprintf(
                'The DSN of the lanes in "%s" names no "%s", so the four lanes of the provider would be one queue: write "%s" where the name of a queue goes, "queue_name=%s" in a DSN of the database, the name of the exchange on a broker.',
                $variable,
                self::PLACEHOLDER,
                self::PLACEHOLDER,
                self::PLACEHOLDER,
            ));
        }

        return str_replace(self::PLACEHOLDER, substr($name, 0, $separator), $dsn);
    }

    /**
     * @return array<string, string>
     */
    public static function getProvidedTypes(): array
    {
        return [self::PREFIX => 'string'];
    }
}
