<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctor;

/**
 * One thing "beffroi:doctor" looks at (issue #196).
 *
 * **It reads and writes nothing.** It is asked when something is already wrong, so it runs on a provider
 * serving traffic, and the first thing support asks for may not be a command that moves the state it is
 * being asked about.
 *
 * **It answers rather than throws**: a doctor that stops on the first thing that is broken is a doctor
 * that never reaches the second, so what a check cannot read is a red finding naming why and not an
 * exception.
 *
 * A point added is a class implementing this and tagged "beffroi.doctor_check", never a branch of the
 * command.
 */
interface CheckInterface
{
    public function finding(): Finding;
}
