<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Http\ProfilePage;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #452, architecture §5.2: a person changes what the tenant lets them change of themselves. The
 * kernel of these tests opens two claims, so both ends of the rule are played: what is open is written,
 * and what is not is refused on the server and not merely left off the page.
 */
final class AccountProfileDescriptionTest extends BrowserTestCase
{
    #[Test]
    public function thePageOffersAFieldPerClaimTheTenantOpens(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->profilePage();

        // Then
        // in the order the claims are wired and not the order the tenant named them, which is what the
        // page says of itself (WiredClaims)
        static::assertSame(['nickname', 'birthdate', 'locale', 'zoneinfo'], $page->filter('form[data-changeable]')->extract(['data-changeable']));
    }

    /**
     * Issue #476: the page renders the field the claim says it is, and a text box stops standing in for
     * every one of them.
     */
    #[Test]
    public function theFieldIsOfTheKindTheClaimSays(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->profilePage();

        // Then
        static::assertSame(['text'], $page->filter('form[data-changeable="nickname"] input[name="value"]')->extract(['data-field']));
        // a browser offers a calendar for a date, and the pattern comes with it for one that does not
        static::assertSame(['date'], $page->filter('form[data-changeable="birthdate"] input[name="value"]')->extract(['data-field']));
        static::assertSame(['\d{4}(-\d{2}-\d{2})?'], $page->filter('form[data-changeable="birthdate"] input[name="value"]')->extract(['pattern']));
    }

    /**
     * Issue #479: a set of several hundred is typed into with the whole set suggested, which is what the
     * languages that exist and the names of the zoneinfo database both are.
     */
    #[Test]
    public function aSetTooLongToReadIsTypedIntoWithTheWholeSetSuggested(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->profilePage();

        // Then
        static::assertSame(['picker'], $page->filter('form[data-changeable="locale"] input[name="value"]')->extract(['data-field']));
        static::assertSame(['picker'], $page->filter('form[data-changeable="zoneinfo"] input[name="value"]')->extract(['data-field']));
        static::assertGreaterThan(400, $page->filter('form[data-changeable="locale"] datalist option')->count());
        static::assertGreaterThan(400, $page->filter('form[data-changeable="zoneinfo"] datalist option')->count());
    }

    /**
     * Issue #479: the name of a language in that language, the only thing recognisable in a list of
     * several hundred.
     */
    #[Test]
    public function aLanguageIsSuggestedUnderItsOwnName(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->profilePage();

        // Then
        static::assertSame(
            ['日本語'],
            $page->filter('form[data-changeable="locale"] datalist option[value="ja"]')->extract(['_text']),
        );
    }

    /**
     * Issue #479: a language this deployment does not serve is one a person may say they read, "locale"
     * being a claim of OIDC Core §5.1 and not a setting of this provider.
     */
    #[Test]
    public function aPersonSaysTheyReadALanguageThisDeploymentDoesNotServe(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->describe('locale', 'ja');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('ja', self::reread($alice)->profile->locale);
    }

    /**
     * Issue #479: what a closed set does not hold is refused on the server, a page that offers a list
     * being a page whose form can be sent with anything.
     */
    #[Test]
    public function aValueTheClosedSetDoesNotHoldIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $page = $this->describe('zoneinfo', 'Europe/Atlantis');

        // Then
        static::assertSame([ProfilePage::REFUSED], $page->filter('p[data-error]')->extract(['data-error']));
        static::assertNull(self::reread($alice)->profile->zoneinfo);
    }

    #[Test]
    public function aNameOfTheZoneinfoDatabaseIsAccepted(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->describe('zoneinfo', 'Pacific/Chatham');

        // Then
        static::assertSame('Pacific/Chatham', self::reread($alice)->profile->zoneinfo);
    }

    #[Test]
    public function aPersonSaysSomethingOfThemselves(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->describe('nickname', 'Ada');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('Ada', self::reread($alice)->profile->nickname);
    }

    #[Test]
    public function anEmptyFieldTakesBackWhatTheyHadSaid(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->describe('nickname', 'Ada');

        // When
        $this->describe('nickname', '');

        // Then
        static::assertNull(self::reread($alice)->profile->nickname);
    }

    /**
     * The page does not offer it, and the form can be sent anyway: what refuses is the server.
     */
    #[Test]
    public function aClaimTheTenantDoesNotOpenIsRefusedOnTheServer(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $page = $this->describe('family_name', 'Lovelace');

        // Then
        static::assertSame([ProfilePage::NOT_OPEN], $page->filter('p[data-error]')->extract(['data-error']));
        static::assertNull(self::reread($alice)->profile->familyName);
    }

    /**
     * Issue #482: the page shows what this person changed of their own record, with what the claim said
     * and what they made it say, which is the question they ask first when they read that they changed
     * something.
     */
    #[Test]
    public function thePageShowsWhatThePersonChangedOfTheirRecord(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->describe('nickname', 'Ada');

        // When
        $page = $this->describe('nickname', 'Augusta');

        // Then
        static::assertSame(['nickname', 'nickname'], $page->filter('tr[data-change]')->extract(['data-change']));
        $last = $page->filter('tr[data-change]')->first()->filter('td');
        static::assertSame('Ada', $last->eq(1)->text());
        static::assertSame('Augusta', $last->eq(2)->text());
    }

    #[Test]
    public function aPersonWhoChangedNothingIsToldSo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->profilePage();

        // Then
        static::assertCount(1, $page->filter('table[data-changes="0"] tr[data-empty]'));
    }

    /**
     * Issue #481: the form answers with a redirection, so reloading the page it came back to does not say
     * the same thing of that person again, and the refusal that crossed the redirection is shown once.
     */
    #[Test]
    public function aFormAnsweredWithARedirectionAndTheRefusalIsShownOnce(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $refused = $this->describe('zoneinfo', 'Europe/Atlantis');

        // Then
        static::assertSame('http://localhost/account/profile', $this->browser->getHistory()->current()->getUri());
        static::assertCount(1, $refused->filter('p[data-error]'));
        static::assertCount(0, $this->profilePage()->filter('p[data-error]'));
    }

    #[Test]
    public function aClaimThisProviderDoesNotHoldIsNothingAtAll(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        // posted here and not through the helper: there is no page to be redirected to about a claim that
        // does not exist, so this one never reaches the use case and never redirects
        $this->browser->request('POST', '/account/profile', [
            '_token' => self::string($this->profilePage()->filter('form[data-changeable="nickname"] input[name="_token"]')->attr('value')),
            'claim' => 'favourite_colour',
            'value' => 'blue',
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aFormSentWithoutTheTokenOfItsPageIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->browser->request('POST', '/account/profile', [
            'claim' => 'nickname',
            'value' => 'Ada',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertNull(self::reread($alice)->profile->nickname);
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefused(): void
    {
        // When
        $this->browser->request('POST', '/account/profile', [
            'claim' => 'nickname',
            'value' => 'Ada',
        ]);

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Saying answers with a redirection (issue #481), so what this reads is the page it comes back to and
     * what was refused is on it.
     */
    private function describe(string $claim, string $value): Crawler
    {
        $token = self::string($this->profilePage()->filter('form[data-changeable="nickname"] input[name="_token"]')->attr('value'));
        $this->browser->request('POST', '/account/profile', [
            '_token' => $token,
            'claim' => $claim,
            'value' => $value,
        ]);

        return $this->afterTheForm();
    }

    private function profilePage(): Crawler
    {
        return $this->browser->request('GET', '/account/profile');
    }

    private static function reread(User $user): User
    {
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }
}
