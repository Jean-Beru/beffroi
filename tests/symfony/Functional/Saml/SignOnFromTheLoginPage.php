<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml S-51, S-61
 */
trait SignOnFromTheLoginPage
{
    private function typeTheAddress(?string $interaction, string $address): void
    {
        $form = $this->browser
            ->request(
                'GET',
                '/login',
                $interaction === null
                    ? []
                    : [
                        'interaction' => $interaction,
                    ],
            )
            ->filter('form[data-step="address"]')
            ->form();
        $form['_address'] = $address;
        $this->browser->submit($form);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
    }

    private function signOnAs(?string $interaction, string $address): Crawler
    {
        $this->typeTheAddress($interaction, $address);

        return $this->browser->followRedirect();
    }
}
