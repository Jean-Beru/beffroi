<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Http\Timeout;
use Beffroi\Bundle\Push\WebPushSender;
use function is_string;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * Whether this deployment reaches its users through the push services of their own browsers (RFC 8030),
 * and what a push service is told to write to when something is wrong with what it is sent.
 *
 * A deployment that names no subject turns web push off: no channel reaches anybody by push, the tenant
 * draws no application server key, and the page where a browser would subscribe says so. That is the
 * default, because how a deployment reaches its users is the one thing about them it cannot be told in
 * advance (architecture §5.6), and a channel nobody asked for is a channel nobody wanted. The subject may be
 * a value of the environment, one only when the container runs, so the channel and the algorithm of the key
 * are wired in every image and listed while the role is on (RoleSwitch); off, that algorithm is dormant, so
 * that a key drawn before the subject was taken away is read by nothing until a subject is named again
 * (DormantKeyAlgorithms).
 */
final readonly class WebPushSection extends ConfigurationSection
{
    /**
     * Seconds one push to one push service is given, connection included. Nobody is waiting on it, but a
     * push service that hangs must not hold a worker.
     */
    public const float DEFAULT_TIMEOUT = 3.0;

    /**
     * The tag a deployment gives a channel of its own in the lane, beside which the channel of web push takes its
     * place while the role is on.
     */
    public const string CHANNEL_TAG = 'beffroi.pending_approval_channel';

    /**
     * The tag an algorithm of a key the tenant hands out is wired by (§3.3), beside which the one of web push is wired
     * while the role is on.
     */
    public const string ALGORITHM_TAG = 'beffroi.application_server_algorithm';

    /**
     * Whether a subject is named, read once when the container builds what web push changes (RoleSwitch).
     */
    public const string ROLE = 'beffroi.web_push.role';

    public function name(): string
    {
        return 'web_push';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('web_push')
            ->info('Reaching a user through the push service of a browser they signed in with (RFC 8030, architecture §5.6). Absent, web push is off: no push leaves this deployment and the page where a browser would subscribe says so.')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('subject')
            ->info('The "sub" of the token this provider signs for a push service (RFC 8292 §2.1): a "mailto:" or "https:" URI at which the operator of this deployment can be reached about what it sends. Naming one is what turns web push on, and none turns it off; it may be an environment variable, read when the container builds what web push changes, which "default::" makes none when it is empty.')
            ->defaultNull()
            ->cannotBeEmpty()
            ->end()
            ->floatNode('timeout')
            ->info('Seconds one push to one push service is given, connection included. A push service that hangs must not hold a worker; how many times it is tried again is the retry policy of the notifications lane, as it is for a logout token.')
            ->defaultValue(self::DEFAULT_TIMEOUT)
            ->min(Timeout::MINIMUM)
            ->end()
            ->end()
            ->end();
    }

    /**
     * The role of web push, which naming a subject turns on: read when the container builds what web push changes, the
     * algorithm of the key the tenant hands out and the channel of the lane, a subject an environment variable carries
     * being one only then.
     *
     * @param string|null $subject the subject the configuration or the environment names, null for none
     *
     * @throws InvalidConfigurationException when the subject is empty, which the tree refuses written
     */
    public static function role(?string $subject): RoleSwitch
    {
        if ($subject !== null) {
            WebPushSender::assertSubject($subject);
        }

        return new RoleSwitch($subject !== null);
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $webPush = $this->own($config);
        $subject = is_string($webPush['subject'] ?? null) ? $webPush['subject'] : null;
        $services
            ->set(self::ROLE, RoleSwitch::class)
            ->factory(self::role(...))
            ->args([$subject]);
        $services->get(WebPushSender::class)->arg('$subject', $subject ?? '')->arg('$timeout', self::timeout($webPush, 'timeout', 'web_push.timeout'));
    }
}
