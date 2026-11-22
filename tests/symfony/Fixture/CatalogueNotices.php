<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Controller\AccountController;
use App\Credential\CredentialChangeNotices;
use App\Locale\Moments;
use App\Locale\ServedLocales;
use App\Locale\UserLocale;
use App\Locale\UserTimeZone;
use function dirname;
use function sprintf;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Translation\Loader\XliffFileLoader;
use Symfony\Component\Translation\Translator;

/**
 * The notices of a change as the catalogues of the application write them, the account page under "/account".
 */
final class CatalogueNotices
{
    private const string CATALOGUE = '%s/apps/beffroi/translations/beffroi+intl-icu.%s.xlf';

    public static function create(): CredentialChangeNotices
    {
        $translator = new Translator('en');
        $translator->addLoader('xlf', new XliffFileLoader());
        foreach (['en', 'fr'] as $locale) {
            $translator->addResource('xlf', sprintf(self::CATALOGUE, dirname(__DIR__, 3), $locale), $locale, 'beffroi+intl-icu');
        }
        $routes = new RouteCollection();
        $routes->add(AccountController::ROUTE, new Route('/account'));

        return new CredentialChangeNotices(
            $translator,
            new UserLocale(new ServedLocales(['en', 'fr'], 'en')),
            new Moments(new UserTimeZone()),
            new UrlGenerator($routes, new RequestContext()),
        );
    }
}
