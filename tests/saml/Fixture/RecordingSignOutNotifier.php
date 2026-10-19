<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use function count;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SentSignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Port\SignOutNotifierInterface;
use function in_array;
use function sprintf;

/**
 * A notifier that keeps the notices it was handed, and tells every service provider but the ones a test says it cannot
 * reach, at "<entity ID>/slo", over HTTP-Redirect or, for the ones a test says, by a form over HTTP-POST, the IDs of
 * its requests numbered in their order.
 */
final class RecordingSignOutNotifier implements SignOutNotifierInterface
{
    /**
     * @var list<SignOutNotice>
     */
    public private(set) array $notices = [];

    /**
     * @param list<string> $unreachable
     * @param list<string> $posting the service providers told over HTTP-POST
     */
    public function __construct(
        private readonly array $unreachable = [],
        private readonly array $posting = [],
    ) {
    }

    public function destination(Tenant $tenant, string $serviceProvider): ?string
    {
        return in_array($serviceProvider, $this->unreachable, true) ? null : $serviceProvider . '/slo';
    }

    public function notify(Tenant $tenant, SignOutNotice $notice): ?SentSignOutNotice
    {
        $destination = $this->destination($tenant, $notice->serviceProvider);
        if ($destination === null) {
            return null;
        }
        $this->notices[] = $notice;
        $id = self::idOf(count($this->notices));
        if (in_array($notice->serviceProvider, $this->posting, true)) {
            return new SentSignOutNotice($id, new PostedForm($destination, ['SAMLRequest' => 'told']));
        }

        return new SentSignOutNotice($id, new RedirectedMessage($destination . '?SAMLRequest=told'));
    }

    /**
     * The ID of the $nth request the notifier wrote.
     */
    public static function idOf(int $nth): string
    {
        return sprintf('_request-%d', $nth);
    }
}
