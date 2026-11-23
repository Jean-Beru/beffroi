<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Confirmation;

use App\Confirmation\AddressConfirmationWording;
use App\Controller\AccountAddressLinkController;
use App\Locale\Moments;
use App\Locale\UserTimeZone;
use App\Message\SendAddressConfirmation;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use function dirname;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Translation\Loader\XliffFileLoader;
use Symfony\Component\Translation\Translator;
use Symfony\Component\Uid\Uuid;

/**
 * NIST SP 800-63B-4 §4.2.1.2, architecture §5.7
 */
final class AddressConfirmationWordingTest extends TestCase
{
    private const string CATALOGUE = '%s/apps/beffroi/translations/beffroi+intl-icu.%s.xlf';

    private const string CONFIRMATION = '0196f7a2-58c1-7d3e-9a4b-2f6c8e1d0a9b';

    private User $alice;

    private Translator $translator;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->translator = new Translator('en');
        $this->translator->addLoader('xlf', new XliffFileLoader());
        foreach (['en', 'fr'] as $locale) {
            $this->translator->addResource('xlf', sprintf(self::CATALOGUE, dirname(__DIR__, 4), $locale), $locale, 'beffroi+intl-icu');
        }
    }

    #[Test]
    public function theCodeAndUntilWhenItHoldsAreWrittenInTheLanguageAndOnTheClockOfThePerson(): void
    {
        // Given
        $this->alice->updateProfile(new Profile(locale: 'fr', zoneinfo: 'Europe/Paris'), Fixtures::now());

        // When
        $body = $this->wording()->body($this->alice, $this->confirmation(), 'fr');

        // Then
        static::assertSame(
            "Votre code de confirmation : 042917, valable jusqu'au 22 nov. 2026, 15:15 UTC+1. Saisissez-le dans votre compte ou ouvrez le lien ci-dessous. Si vous n'avez rien demandé, ignorez ce message.",
            $body,
        );
    }

    #[Test]
    public function theLinkLeadsToThePageOfTheProviderUnderTheOriginOfTheIssuer(): void
    {
        // When
        $link = $this->wording()->link($this->confirmation());

        // Then
        static::assertSame(sprintf('https://id.acme.example/account/addresses/phone_number/%s/the-value-of-the-link', self::CONFIRMATION), $link);
    }

    private function wording(): AddressConfirmationWording
    {
        $routes = new RouteCollection();
        $routes->add(AccountAddressLinkController::ROUTE, new Route('/account/addresses/{claim}/{confirmation}/{value}'));

        return new AddressConfirmationWording($this->translator, new Moments(new UserTimeZone()), new UrlGenerator($routes, new RequestContext()));
    }

    private function confirmation(): SendAddressConfirmation
    {
        return new SendAddressConfirmation(
            $this->alice->tenant,
            $this->alice->id,
            'phone_number',
            '+33612345678',
            Uuid::fromString(self::CONFIRMATION),
            '042917',
            'the-value-of-the-link',
            new DateTimeImmutable('2026-11-22T14:15:00+00:00'),
        );
    }
}
