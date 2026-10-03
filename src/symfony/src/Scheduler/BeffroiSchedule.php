<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Scheduler;

use Beffroi\Bundle\Message\AdvanceKeyLifecycle;
use Beffroi\Bundle\Message\ForgetTheActsPastTheirRetention;
use Beffroi\Bundle\Message\ForgetTheExpiredArchives;
use Beffroi\Bundle\Message\RemoveUnusedClients;
use Symfony\Component\Scheduler\Attribute\AsSchedule;
use Symfony\Component\Scheduler\RecurringMessage;
use Symfony\Component\Scheduler\Schedule;
use Symfony\Component\Scheduler\ScheduleProviderInterface;

/**
 * What time does on its own (architecture §5.6): one recurring message per timed step, handled on the
 * command bus like every write. The transport is "scheduler_beffroi"; the worker that consumes the buses
 * consumes it too, and one worker at a time does, the steps being idempotent but not concurrent.
 */
#[AsSchedule(BeffroiSchedule::NAME)]
final readonly class BeffroiSchedule implements ScheduleProviderInterface
{
    public const string NAME = 'beffroi';

    /**
     * The precision of the two windows of a rotation, minutes long at the least.
     */
    public const string KEY_LIFECYCLE_EVERY = '1 minute';

    /**
     * What the removal of the clients nobody uses any more is worth waiting for (decision 0009): the
     * durations it reads are days long, a run is bounded and the next one takes what it left, so an hour is
     * short enough that a backlog is worked through and long enough that a deployment with nothing to drop
     * reads its table once an hour and no more.
     */
    public const string UNUSED_CLIENTS_EVERY = '1 hour';

    /**
     * What the retention of the journal is worth waiting for (issue #454): the duration it reads is months
     * long, a run is bounded and the next one takes what it left, so a day is short enough that a backlog
     * is worked through and long enough that a deployment with nothing to forget reads its journal once a
     * day and no more.
     */
    public const string JOURNAL_RETENTION_EVERY = '1 day';

    /**
     * What forgetting an expired archive is worth waiting for (issue #453). An hour and not a day, where
     * the journal waits a day: an archive is the one file in which everything this provider knows of a
     * person stands in clear at once, so the window between the moment it is worth nothing and the moment
     * it is gone is the one window this schedule keeps short.
     */
    public const string EXPIRED_ARCHIVES_EVERY = '1 hour';

    public function getSchedule(): Schedule
    {
        return new Schedule()
            ->add(RecurringMessage::every(self::KEY_LIFECYCLE_EVERY, new AdvanceKeyLifecycle()))
            ->add(RecurringMessage::every(
                self::UNUSED_CLIENTS_EVERY,
                new RemoveUnusedClients(),
            ))
            ->add(RecurringMessage::every(self::JOURNAL_RETENTION_EVERY, new ForgetTheActsPastTheirRetention()))
            ->add(RecurringMessage::every(
                self::EXPIRED_ARCHIVES_EVERY,
                new ForgetTheExpiredArchives(),
            ));
    }
}
