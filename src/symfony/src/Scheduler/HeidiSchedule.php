<?php

declare(strict_types=1);

namespace Heidi\Bundle\Scheduler;

use Heidi\Bundle\Message\AdvanceKeyLifecycle;
use Symfony\Component\Scheduler\Attribute\AsSchedule;
use Symfony\Component\Scheduler\RecurringMessage;
use Symfony\Component\Scheduler\Schedule;
use Symfony\Component\Scheduler\ScheduleProviderInterface;

/**
 * What time does on its own (architecture §5.6): one recurring message per timed step, handled on the
 * command bus like every write. The transport is "scheduler_heidi"; the worker that consumes the buses
 * consumes it too, and one worker at a time does, the steps being idempotent but not concurrent.
 */
#[AsSchedule(HeidiSchedule::NAME)]
final readonly class HeidiSchedule implements ScheduleProviderInterface
{
    public const string NAME = 'heidi';

    /**
     * The precision of the two windows of a rotation, minutes long at the least.
     */
    public const string KEY_LIFECYCLE_EVERY = '1 minute';

    public function getSchedule(): Schedule
    {
        return new Schedule()
            ->add(RecurringMessage::every(self::KEY_LIFECYCLE_EVERY, new AdvanceKeyLifecycle()));
    }
}
