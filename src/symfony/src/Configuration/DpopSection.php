<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Dpop\CachedDpopNonce;
use Beffroi\Bundle\Dpop\DpopNonceRequirement;
use Beffroi\Oidc\Application\Dpop\DpopProofValidator;
use Beffroi\Oidc\Bridge\Null\NoDpopNonce;
use Beffroi\Oidc\Port\DpopNonceInterface;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_closure;

/**
 * What the provider allows of a proof of possession (RFC 9449 §11.1), and whether it asks a proof to carry a nonce of its own (§8).
 */
final readonly class DpopSection extends ConfigurationSection
{
    /**
     * RFC 9449 §11.1: how long a proof stands, from its "iat", before the leeway below is added. A proof
     * is made for one request that is being sent; what the window has to cover is the time that request
     * spends on the wire, and every second beyond it is a second a proof taken off that wire may be sent
     * again.
     */
    public const int DEFAULT_DPOP_PROOF_MAX_AGE = 60;

    /**
     * What is allowed of the clock of a client, both ways. Thirty seconds and not five: a client whose
     * clock runs ahead makes a proof dated after the request that carries it, and the conformance suite
     * of FAPI 2 makes one ten seconds ahead and expects it taken (RFC 9449 §11.1 leaves the window to
     * the provider). The other way is the age of a proof: a client whose clock runs behind dates a proof
     * before it was made, so a proof is taken until "proof_max_age" plus the leeway after its "iat",
     * ninety seconds by default.
     */
    public const int DEFAULT_DPOP_LEEWAY = 30;

    /**
     * Seconds a nonce this provider issues is accepted (RFC 9449 §8), for a deployment that asks for
     * one; a client is handed a fresh one whenever it presents none or one this window has passed.
     */
    public const int DEFAULT_DPOP_NONCE_TTL = 300;

    public function name(): string
    {
        return 'dpop';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('dpop')
            ->info('How a proof of possession is read (RFC 9449 §4.3). What a proof may be signed with is the wiring, the same algorithms the provider signs with, and what the document announces in "dpop_signing_alg_values_supported"; nothing here weakens a proof, and a client that sends none is not concerned.')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('proof_max_age')
            ->info('Seconds a proof stands, from its "iat", before the leeway is added (RFC 9449 §4.3). A proof is a signature over one request being sent; a long window is a window a proof taken off the wire may be sent again in.')
            ->defaultValue(self::DEFAULT_DPOP_PROOF_MAX_AGE)
            ->min(1)
            ->end()
            ->integerNode('leeway')
            ->info('Seconds allowed of the clock of a client, both ways: a proof is taken up to this many seconds ahead of the clock of the provider, and until "proof_max_age" plus this many seconds after its "iat".')
            ->defaultValue(self::DEFAULT_DPOP_LEEWAY)
            ->min(0)
            ->end()
            ->arrayNode('nonce')
            ->info('Whether this provider asks a proof to carry a nonce of its own (RFC 9449 §8), which is the server\'s to decide: the "iat" of a proof is what its client says, a nonce is what the provider knows. A client that speaks DPoP handles the refusal that hands it one; one that does not is not concerned either way.')
            ->addDefaultsIfNotSet()
            ->children()
            ->booleanNode('required')
            ->defaultFalse()
            ->end()
            ->integerNode('ttl')
            ->info('Seconds a nonce is accepted once issued.')
            ->defaultValue(self::DEFAULT_DPOP_NONCE_TTL)
            ->min(1)
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $dpop = $this->own($config);
        $nonces = self::section($dpop, 'nonce');
        $services->get(DpopProofValidator::class)->arg('$maximumAge', self::seconds($dpop, 'proof_max_age'))->arg('$leeway', self::seconds($dpop, 'leeway'));
        $services->get(CachedDpopNonce::class)->arg('$lifetime', self::seconds($nonces, 'ttl'));
        // what the provider asks of a proof is a class it is wired with, never a flag read at every request;
        // the flag is read once, when the port is built, so that an environment variable can carry it
        $services
            ->set(DpopNonceInterface::class)
            ->factory(DpopNonceRequirement::chosen(...))
            ->args([
                self::boolean($nonces, 'required'),
                service_closure(CachedDpopNonce::class),
                service_closure(NoDpopNonce::class),
            ]);
    }
}
