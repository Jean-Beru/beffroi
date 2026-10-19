<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Key;

use Beffroi\Core\Bridge\Algorithm\WiredAlgorithms;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;

/**
 * The algorithms of the keys a capability of the bundle draws when a deployment turns it on, tagged by the section
 * of the configuration that owns the capability when the deployment left it off (spec/saml.md section 5.1): the SAML
 * signing key under "beffroi.saml.identity_provider", the application server key under "beffroi.web_push".
 *
 * A key file that names one is a key the tenant drew while the capability was on. It stays where it is and the key
 * files read past it, so that it is neither served, nor rotated, nor drawn again, and it is back in service as it was
 * the day the capability is turned on again. What a section leaves off is the one thing that tags here, so the names
 * are those of the algorithms themselves and no list of them is kept anywhere else; a name that neither the wiring
 * nor this knows is still a fault of the storage.
 */
final readonly class DormantKeyAlgorithms
{
    /**
     * The tag a section puts on the algorithm of a capability it leaves off.
     */
    public const string TAG = 'beffroi.dormant_key_algorithm';

    /**
     * @var WiredAlgorithms<KeyAlgorithmInterface>
     */
    private WiredAlgorithms $dormant;

    /**
     * @param iterable<KeyAlgorithmInterface> $algorithms
     */
    public function __construct(iterable $algorithms = [])
    {
        $this->dormant = new WiredAlgorithms($algorithms);
    }

    public function holds(string $name): bool
    {
        return $this->dormant->named($name) !== null;
    }
}
