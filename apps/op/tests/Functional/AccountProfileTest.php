<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of what this provider holds of the signed-in person, which is this application's and not the
 * bundle's (issue beffroi-auth/op#17), judged on the kernel this application deploys: the claims its own
 * tenant opens, the form component it alone installs, and the stylesheet that makes the editing in place.
 *
 * What the bundle's own page does is judged by the suite of the bundle. What is here is what only this
 * kernel can answer.
 */
final class AccountProfileTest extends BrowserTestCase
{
    /**
     * The one refusal the controller of this application does not write itself (`AccountAccess`), kept here
     * because it is also what says the kernel of the application boots and serves this route at all: a
     * deployment that routed it elsewhere, or a firewall that answered before the page, would be red here
     * and nowhere else.
     */
    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/account/profile');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * Issue beffroi-auth/beffroi#452: what a person may change is what the tenant opens, and the tenant of an
     * image that names nothing opens fourteen claims (BEFFROI_TENANT_SELF_SERVED_CLAIMS of .env). The page is
     * one list of what the record holds, so they are offered in the order the record is read in and not in the
     * order the tenant named them: a line is where the reader expects the claim, whether they may change it or
     * only read it.
     */
    #[Test]
    public function thePageOffersAFormPerClaimTheTenantOpens(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->profilePage();

        // Then
        static::assertSame([
            'phone_number',
            'name',
            'given_name',
            'family_name',
            'middle_name',
            'nickname',
            'preferred_username',
            'birthdate',
            'gender',
            'locale',
            'zoneinfo',
            'profile',
            'picture',
            'website',
        ], $page->filter('form[data-editable]')->extract(['data-editable']));
    }

    /**
     * Issue beffroi-auth/op#17: the message goes under the line it is about, which is the whole reason this
     * application installs a form component where the page of the bundle says one sentence for the page.
     * The refusal here is the claim's own, a name the zoneinfo database does not carry, and it is made on
     * the server: the page offers the set as suggestions, so its form can be sent with anything.
     */
    #[Test]
    public function aRefusedValueIsSaidUnderTheFieldItIsAbout(): void
    {
        // Given
        $alice = self::user();
        $this->signIn($alice);

        // When
        $page = $this->describe('zoneinfo', 'Europe/Atlantis');

        // Then
        static::assertSame(
            ['That is not a value this provider can hold for that.'],
            $page->filter('form[data-editable="zoneinfo"] ul li')->extract(['_text']),
        );
        static::assertCount(0, $page->filter('form[data-editable="nickname"] ul li'));
        static::assertNull(self::reread($alice)->profile->zoneinfo);
    }

    /**
     * Issue beffroi-auth/beffroi#887, OIDC Core §5.1: a day whose year is withheld is held under the year
     * "0000", which a date input does not carry (HTML §2.3.5.1), so the form of the component offers a line
     * of text that holds it and not a calendar that renders it empty.
     */
    #[Test]
    public function aBirthdateWhoseYearIsWithheldIsOfferedAsALineOfText(): void
    {
        // Given
        $alice = self::user();
        $alice->updateProfile(new Profile(birthdate: '0000-05-21'), self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);
        $this->signIn($alice);

        // When
        $page = $this->profilePage();

        // Then
        $field = $page->filter('form[data-editable="birthdate"] input[name="claim[value]"]');
        static::assertSame(['text'], $field->extract(['type']));
        static::assertSame(['0000-05-21'], $field->extract(['value']));
    }

    /**
     * Issue beffroi-auth/op#17: what a person says of themselves on this page is what the use case of the
     * core writes, the form of the component carrying it there and nothing else.
     */
    #[Test]
    public function whatAPersonSaysOfThemselvesIsWritten(): void
    {
        // Given
        $alice = self::user();
        $this->signIn($alice);

        // When
        $this->describe('nickname', 'Al');

        // Then
        static::assertSame('Al', self::reread($alice)->profile->nickname);
    }

    /**
     * Issue beffroi-auth/op#17: the editing in place is a stylesheet and not a behaviour, so a browser that
     * runs nothing is served a field and a button that work. A script on this page would be a page that
     * needs one.
     */
    #[Test]
    public function thePageRunsNoScript(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->profilePage();

        // Then
        static::assertCount(0, $page->filter('script'));
        static::assertCount(0, $page->filter('[onclick], [onchange], [onsubmit]'));
    }

    /**
     * The form of one claim, submitted with the value given, and the page the redirection it answers with
     * names (issue beffroi-auth/beffroi#522).
     */
    private function describe(string $claim, string $value): Crawler
    {
        $form = $this->profilePage()->filter(sprintf('form[data-editable="%s"]', $claim))->form();
        $form->setValues([
            'claim[value]' => $value,
        ]);
        $this->browser->submit($form);

        return $this->afterTheForm();
    }

    private function profilePage(): Crawler
    {
        return $this->page('/account/profile');
    }
}
