<?php

declare(strict_types=1);

namespace App\Key;

use Beffroi\Core\Bridge\Algorithm\WiredAlgorithms;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use function str_starts_with;

/**
 * The algorithms of the keys a capability of the provider draws while a deployment has it on, tagged in every image by
 * the wiring of the capability (spec/saml.md section 5.1): the SAML signing key of "beffroi.saml", the application
 * server key of "beffroi.web_push". Whether the capability is on is read when the container builds the registry of its
 * family (RoleSwitch, SwitchedServices), and the key files ask here only of a name that registry does not carry, so
 * an algorithm held here is dormant exactly while its capability is off.
 *
 * A key file that names one is then a key the tenant drew while the capability was on. It stays where it is and the
 * key files read past it, so that it is neither served, nor rotated, nor drawn again, and it is back in service as it
 * was the day the capability is turned on again. The names are those of the algorithms themselves and no list of them
 * is kept anywhere else; a name that neither the wiring nor this knows is still a fault of the storage.
 *
 * A family whose algorithms are one per holder, the keys the upstream SAML identity providers encrypt for, one per
 * provider declared (spec/saml.md S-64), is known here by what the names of its algorithms begin with: a provider no
 * longer declared has no algorithm wired to tag, and its key is read past as the key of a capability turned off.
 */
final readonly class DormantKeyAlgorithms
{
    /**
     * The tag the algorithm of a capability a deployment may leave off is given in every image.
     */
    public const string TAG = 'beffroi.dormant_key_algorithm';

    /**
     * @var WiredAlgorithms<KeyAlgorithmInterface>
     */
    private WiredAlgorithms $dormant;

    /**
     * @param iterable<KeyAlgorithmInterface> $algorithms
     * @param list<string> $families what the names of the algorithms of a family begin with, one algorithm per holder
     */
    public function __construct(
        iterable $algorithms = [],
        private array $families = [],
    ) {
        $this->dormant = new WiredAlgorithms($algorithms);
    }

    public function holds(string $name): bool
    {
        foreach ($this->families as $family) {
            if (str_starts_with($name, $family)) {
                return true;
            }
        }

        return $this->dormant->named($name) !== null;
    }
}
