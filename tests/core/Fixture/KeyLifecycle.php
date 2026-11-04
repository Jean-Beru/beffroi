<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use DateInterval;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeySuccession;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Application\Key\NamedKey;
use Beffroi\Core\Application\Key\RetirementWindow;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Core\Port\KeyPairGeneratorInterface;
use Psr\Clock\ClockInterface;

final readonly class KeyLifecycle
{
    public const string LONGEST_LIFETIME = 'PT1H';

    public const string STAGING_DELAY = 'PT6M';

    public const string AGE = 'P30D';

    public InMemoryTenantKeyRepository $keys;

    public RecordingEventDispatcher $events;

    public RetirementWindow $window;

    public KeyStaging $staging;

    public KeyRetirement $retirement;

    public KeyTakeOver $takeOver;

    public KeySuccession $succession;

    /**
     * @param list<KeyBoundArtifactInterface>|null $artifacts
     * @param array<string, RotationSchedule> $families by algorithm name
     */
    public function __construct(
        ClockInterface $clock,
        ?array $artifacts = null,
        ?string $age = null,
        ?KeyPairGeneratorInterface $generator = null,
        array $families = [],
    ) {
        $schedules = new FixedRotationSchedules(
            new RotationSchedule(new DateInterval(self::STAGING_DELAY), new DateInterval($age ?? self::AGE)),
            $families,
        );
        $this->keys = new InMemoryTenantKeyRepository();
        $this->events = new RecordingEventDispatcher();
        $this->window = new RetirementWindow(
            $artifacts ?? [
                new FixedLifetimeArtifact(new DateInterval('PT10M')),
                new FixedLifetimeArtifact(new DateInterval(self::LONGEST_LIFETIME)),
            ],
        );
        $named = new NamedKey($this->keys);
        $this->staging = new KeyStaging(
            $this->keys,
            $generator ?? new PrecomputedKeyPairGenerator([Keys::pair(), Keys::otherPair()]),
            Keys::sealer(),
            $schedules,
            $clock,
            $this->events,
        );
        $this->retirement = new KeyRetirement($this->keys, $named, $clock, $this->events);
        $this->takeOver = new KeyTakeOver(
            $this->keys,
            $named,
            $this->staging,
            $this->window,
            $this->retirement,
            $clock,
            $this->events,
        );
        $this->succession = new KeySuccession(
            $this->keys,
            $this->staging,
            $this->window,
            $schedules,
            $clock,
        );
    }
}
