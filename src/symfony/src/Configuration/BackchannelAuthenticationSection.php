<?php

declare(strict_types=1);

namespace Heidi\Bundle\Configuration;

use Heidi\Bundle\Http\ClientNotificationSender;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * What a backchannel authentication request of this tenant may name its user by, and what one call back to a client may cost (CIBA Core §7.1, §10.2). Which delivery modes the provider serves is the wiring and not this: a mode is a tagged service, and what is tagged is what is announced.
 */
final readonly class BackchannelAuthenticationSection extends ConfigurationSection
{
    /**
     * Seconds one call to a client notification endpoint is given, connection included. Nobody is waiting
     * on it, but a client that hangs must not hold a worker.
     */
    public const float DEFAULT_NOTIFICATION_TIMEOUT = 3.0;

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
            ->info('What a "login_hint" of a backchannel authentication request names for this tenant, read one way and never searched for (CIBA Core §7.1): "sub" the subject this provider issued to that client, "username" the name the user signs in with, "none" for a deployment that tags a reader of its own. CIBA Core §15 asks for an identifier that says nothing outside this provider, which "sub" is and a username is not. These are the names the login page reads its own hint by.')
            ->values(LoginHintReadings::names())
            ->defaultValue(LoginHintReadings::DEFAULT)
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
        LoginHintReadings::tag($services, self::string($backchannel, 'login_hint'), 'heidi.oidc.ciba_user_hint');
    }
}
