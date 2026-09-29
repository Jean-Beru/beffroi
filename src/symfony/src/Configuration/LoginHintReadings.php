<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use function array_keys;
use Heidi\Oidc\Application\Hint\SubjectLoginHint;
use Heidi\Oidc\Application\Hint\UsernameLoginHint;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * The ways the bundle ships of reading a "login_hint", by the name a deployment picks one with. It is one
 * list and not two: the authorization request a browser carries (OIDC Core §3.1.2.1) and the backchannel
 * authentication request a client makes (CIBA Core §7.1) carry the same parameter, so a deployment names
 * the same readings on both sides rather than learning a vocabulary per side.
 *
 * A deployment whose clients name their users some other way tags a UserHintInterface of its own and says
 * "none"; two things reading one parameter is a wiring with two answers, and is refused where the hint is
 * read rather than allowed to pick one.
 */
final readonly class LoginHintReadings
{
    /**
     * CIBA Core §15: the subject, which says who somebody is to this provider and to this client, and
     * nowhere else.
     */
    public const string DEFAULT = 'sub';

    /**
     * What a deployment that tags a reading of its own says, there being nothing of the bundle to wire.
     */
    private const string NONE = 'none';

    /**
     * @var array<string, class-string>
     */
    private const array READINGS = [
        'sub' => SubjectLoginHint::class,
        'username' => UsernameLoginHint::class,
    ];

    /**
     * @return list<string>
     */
    public static function names(): array
    {
        return [...array_keys(self::READINGS), self::NONE];
    }

    /**
     * Tags the reading a deployment named for that side of the provider, and nothing at all when it named
     * "none".
     */
    public static function tag(ServicesConfigurator $services, string $name, string $tag): void
    {
        $reading = self::READINGS[$name] ?? null;
        if ($reading === null) {
            return;
        }

        $services->get($reading)->tag($tag);
    }
}
