<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use function file_get_contents;
use function is_string;
use LogicException;
use Symfony\Component\Process\ExecutableFinder;

/**
 * The certificates and the keys of Fixture/mail: drawn for the suite, valid from 2020 to 2126 unless their name says
 * expired, the S/MIME ones of the sender issued by "Acme Test CA".
 */
final class MailFixtures
{
    public static function read(string $name): string
    {
        $content = file_get_contents(__DIR__ . '/mail/' . $name);
        if (! is_string($content)) {
            throw new LogicException('No fixture ' . $name);
        }

        return $content;
    }

    /**
     * The path of gpg, or null on a machine that carries none, the image of the QA tools among them.
     */
    public static function gpg(): ?string
    {
        return new ExecutableFinder()->find('gpg');
    }
}
