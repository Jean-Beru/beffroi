<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tenant;

use Beffroi\Bundle\Configuration\TenantSection;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Bundle\Identity\WiredClaims;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Exception\InvalidArgumentException;
use function implode;
use function is_string;
use function sprintf;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The tenant of the "beffroi.tenant" configuration (architecture §5.1); its identifier derives from its
 * slug, so renaming the slug is creating another tenant. Its "acr" policy is the configured classes in
 * their order (decision 0010); what the policy refuses refuses the start.
 */
final readonly class TenantFactory
{
    /**
     * RFC 9562 §6.6, fixed for the life of the project.
     */
    private const string NAMESPACE = '55ade059-fda4-45f4-96ca-43dc8ef74d3e';

    /**
     * @param array<array-key, string> $authenticationClasses class name to predicate, in order
     * @param array<array-key, mixed> $selfServedClaims the names of "beffroi.tenant.self_served_claims"
     * @param WiredClaims|null $claims the claims this provider holds, against which those names are read
     * @param array<array-key, mixed> $look the "beffroi.tenant.look" section, every value of it absent or
     *                                      null for a deployment that declares no look (issue #449)
     */
    public function __construct(
        private string $issuer,
        private string $slug,
        private ?string $name,
        private ClockInterface $clock,
        private array $authenticationClasses = TenantSection::DEFAULT_AUTHENTICATION_CLASSES,
        private array $look = [],
        private array $selfServedClaims = [],
        private ?WiredClaims $claims = null,
    ) {
    }

    public function create(): Tenant
    {
        $issuer = new Issuer($this->issuer);

        return new Tenant(
            self::identifier($this->slug),
            $this->slug,
            $issuer,
            $this->name ?? $issuer->host,
            $this->clock->now(),
            $this->authenticationContextPolicy(),
            $this->look(),
            $this->selfServedClaims(),
        );
    }

    /**
     * What the configuration says a person may change of themselves, read against the claims this provider
     * holds: a name no wired claim answers is a mistake nobody would see on a page, so it refuses the
     * start, as a policy of authentication classes that does not hold does.
     */
    public function selfServedClaims(): SelfServedClaims
    {
        $names = [];
        foreach ($this->selfServedClaims as $name) {
            if (! is_string($name)) {
                throw new InvalidArgumentException('A claim a person may change of themselves is named by a string.');
            }
            if ($this->claims !== null && $this->claims->named($name) === null) {
                throw new InvalidArgumentException(sprintf(
                    'This provider holds no claim "%s" a person could change of themselves; it holds %s.',
                    $name,
                    implode(', ', $this->claims->names()),
                ));
            }
            $names[] = $name;
        }

        return new SelfServedClaims($names);
    }

    /**
     * What the configuration declares of the look of this tenant; the value object refuses a colour that
     * is not hexadecimal and a logo that is not an absolute HTTPS URL, which is what makes a mistake in
     * the configuration refuse the start rather than reach a page.
     */
    public function look(): TenantLook
    {
        $logoUri = $this->look['logo_uri'] ?? null;
        $primaryColor = $this->look['primary_color'] ?? null;
        $primaryContentColor = $this->look['primary_content_color'] ?? null;

        return new TenantLook(
            is_string($logoUri) ? new LogoUri($logoUri) : null,
            is_string($primaryColor) ? $primaryColor : null,
            is_string($primaryContentColor) ? $primaryContentColor : null,
        );
    }

    public function authenticationContextPolicy(): AuthenticationContextPolicy
    {
        $classes = [];
        foreach ($this->authenticationClasses as $name => $predicate) {
            $classes[] = new AuthenticationContextClass((string) $name, AuthenticationPredicate::from($predicate));
        }

        return new AuthenticationContextPolicy($classes);
    }

    public static function identifier(string $slug): Uuid
    {
        return Uuid::v5(Uuid::fromString(self::NAMESPACE), $slug);
    }
}
