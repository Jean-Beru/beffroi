<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Heidi\Bundle\Http\ClientNotificationSender;
use Heidi\Oidc\Application\Ciba\Hint\SubjectLoginHint;
use Heidi\Oidc\Application\Ciba\Hint\UsernameLoginHint;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * What a backchannel authentication request of this tenant may name its user by, and what one call back to a client may cost (CIBA Core §7.1, §10.2). Which delivery modes the provider serves is the wiring and not this: a mode is a tagged service, and what is tagged is what is announced.
 */
final readonly class BackchannelAuthenticationSection extends ConfigurationSection
{
    /**
     * CIBA Core §15: the subject, which says who somebody is to this provider and to this client, and
     * nowhere else.
     */
    public const string DEFAULT_LOGIN_HINT = 'sub';

    /**
     * Seconds one call to a client notification endpoint is given, connection included. Nobody is waiting
     * on it, but a client that hangs must not hold a worker.
     */
    public const float DEFAULT_NOTIFICATION_TIMEOUT = 3.0;

    /**
     * The ways the bundle ships of reading a "login_hint", by the name a deployment picks one with. A
     * deployment whose clients name their users some other way tags a UserHintInterface of its own and
     * says "none" here; two things reading one parameter is a wiring with two answers and is refused.
     *
     * @var array<string, class-string>
     */
    private const array LOGIN_HINTS = [
        'sub' => SubjectLoginHint::class,
        'username' => UsernameLoginHint::class,
    ];

    public function name(): string
    {
        return 'backchannel_authentication';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('backchannel_authentication')
            ->info('The flow where a client asks for a user it names and the user approves on a device they already hold (CIBA Core §7). A client takes part in it by registering a grant and a delivery mode, one client at a time; nothing here turns it on for anybody.')
            ->addDefaultsIfNotSet()
            ->children()
            ->enumNode('login_hint')
            ->info('What a "login_hint" names for this tenant, read one way and never searched for (CIBA Core §7.1): "sub" the subject this provider issued to that client, "username" the name the user signs in with, "none" for a deployment that tags a reader of its own. CIBA Core §15 asks for an identifier that says nothing outside this provider, which "sub" is and a username is not.')
            ->values(['sub', 'username', 'none'])
            ->defaultValue(self::DEFAULT_LOGIN_HINT)
            ->end()
            ->floatNode('client_notification_timeout')
            ->info('Seconds one call to a client notification endpoint is given, connection included (CIBA Core §10.2). A client that hangs must not hold a worker; how many times the call is tried again is the retry policy of the notifications lane, as it is for a logout token.')
            ->defaultValue(self::DEFAULT_NOTIFICATION_TIMEOUT)
            ->min(0.1)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $backchannel = $this->own($config);
        $services->get(ClientNotificationSender::class)->arg('$timeout', self::float($backchannel, 'client_notification_timeout'));
        $hint = self::LOGIN_HINTS[self::string($backchannel, 'login_hint')] ?? null;
        if ($hint !== null) {
            $services->get($hint)->tag('heidi.oidc.ciba_user_hint');
        }
    }
}
