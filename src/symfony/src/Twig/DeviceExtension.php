<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Twig;

use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\RequestContext;
use Symfony\Contracts\Translation\TranslatorInterface;
use Twig\Attribute\AsTwigFilter;

/**
 * The browser a provenance came from, as the person in front of the page reads it (architecture §3.5):
 * the browser and the system, joined in the language of the page, where sixteen tokens of a user agent
 * say nothing to somebody looking for the browser they used.
 *
 * **The device a row carries is what it says, and the agent is read when it carries none** (Device): the
 * reading is the same one either way, so a row written before anything read a user agent reads like a row
 * written after.
 *
 * **What the reading recognises nothing in is written as it stands.** A user agent is a string a browser
 * sent and nobody verified, so a page showing a name this provider invented for it would be showing
 * something nobody can check; what is not a browser says what it is in a few characters, and the page
 * keeps the whole of what was sent beside it either way.
 */
final readonly class DeviceExtension
{
    public function __construct(
        private TranslatorInterface $translator,
    ) {
    }

    #[AsTwigFilter(name: 'beffroi_device')]
    public function device(?RequestContext $provenance): ?string
    {
        if ($provenance === null) {
            return null;
        }
        $device = $provenance->device ?? Device::readFrom($provenance->userAgent);
        if ($device === null) {
            return $provenance->userAgent;
        }
        if ($device->browser !== null && $device->platform !== null) {
            return $this->translator->trans(
                'provenance.device',
                [
                    'browser' => $device->browser,
                    'platform' => $device->platform,
                ],
                'beffroi',
            );
        }

        return $device->browser ?? $device->platform ?? $provenance->userAgent;
    }
}
