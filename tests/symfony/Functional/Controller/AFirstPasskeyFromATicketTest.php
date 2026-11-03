<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Enrolment\IssuedEnrolmentTicket;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #613: a person poses their first passkey from the URL an administrator handed them, with no
 * session and nothing to sign in with, on a tenant that signs its users in by passkey (decision 0025).
 * The walk ends where the product claim is: they sign in with what they have just posed.
 */
final class AFirstPasskeyFromATicketTest extends PasskeyTestCase
{
    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
        // the case the ticket exists for: a person created after the tenant hardened, with no password
        $this->alice = self::user('alice');
        self::harden(new PhishingResistant());
        self::reload();
    }

    #[Test]
    public function theLinkOpensAPageThatNamesTheAccountItIsFor(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $page = $this->ticketPage($issued);

        // Then
        static::assertStringContainsString('alice', self::string($page->filter('p')->first()->text()));
        static::assertCount(1, $page->filter('form[data-passkey="enrol"]'));
    }

    /**
     * The whole of it: the page, the ceremony, the passkey in the rows, the ticket spent, and the person
     * signed in by what they just posed.
     */
    #[Test]
    public function thePersonPosesAPasskeyAndSignsInWithIt(): void
    {
        // Given
        $issued = $this->issue();
        $device = self::device();

        // When
        $this->poseAPasskey($issued, $device);

        // Then
        static::assertSame(Response::HTTP_SEE_OTHER, $this->browser->getResponse()->getStatusCode());
        static::assertCount(1, self::events(CredentialEnrolled::class));
        static::assertCount(1, self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->findByUser($this->alice, PasskeyCredential::class));

        // and the point of it all: they sign in with what they posed
        $this->forgetTheBrowser();
        self::forgetEvents();
        $this->loginWithPasskey($this->authorize(), $device);
        static::assertCount(1, self::events(UserAuthenticated::class));
        static::assertTrue($this->isBoundToASession());
    }

    #[Test]
    public function theLinkOpensNothingASecondTime(): void
    {
        // Given
        $issued = $this->issue();
        $this->poseAPasskey($issued, self::device());
        $this->forgetTheBrowser();

        // When
        $this->browser->request('GET', $this->path($issued));

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aLinkOutOfTimeOpensNothing(): void
    {
        // Given
        $issued = $this->issue();

        // When
        self::mockTime(self::currentSecond()->modify('+73 hours'));
        $this->browser->request('GET', $this->path($issued));

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aValueThatIsNotTheOneOpensNothing(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->browser->request('GET', '/enrol/' . $issued->ticket->id->toRfc4122() . '/not-the-value-of-that-link');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function anIdentifierNothingAnswersOpensNothing(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->browser->request('GET', '/enrol/' . Uuid::v7()->toRfc4122() . '/' . $issued->value);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The form of the page is read with its token: a ceremony posted without it is refused as every form
     * of this provider is.
     */
    #[Test]
    public function aCeremonyPostedWithoutTheTokenOfThePageIsRefused(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->browser->request('POST', $this->path($issued), [
            '_token' => 'not the token of the page',
            '_passkey' => '{}',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], self::events(CredentialEnrolled::class));
    }

    /**
     * The person is read again from the rows: what the fixture holds was detached when the identity map
     * was cleared, and a ticket names a person the entity manager manages.
     */
    private function issue(): IssuedEnrolmentTicket
    {
        $alice = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($this->alice->id) ?? static::fail('The person is gone.');
        $issued = self::service('test.beffroi.enrolment_tickets', EnrolmentTicketIssue::class)->issue($alice, self::context());
        self::forgetEvents();

        return $issued;
    }

    private function path(IssuedEnrolmentTicket $issued): string
    {
        return '/enrol/' . $issued->ticket->id->toRfc4122() . '/' . $issued->value;
    }

    private function ticketPage(IssuedEnrolmentTicket $issued): Crawler
    {
        $crawler = $this->browser->request('GET', $this->path($issued));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * The ceremony as the page does it: the options fetched, the attestation posted with the token of the
     * page.
     */
    private function poseAPasskey(IssuedEnrolmentTicket $issued, SoftwareAuthenticator $device): void
    {
        $token = $this->ticketPage($issued)->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);
        $this->browser->request('POST', $this->path($issued) . '/options');
        $options = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $options->getStatusCode(), self::string($options->getContent()));
        $this->browser->request('POST', $this->path($issued), [
            '_token' => $token,
            '_passkey' => $device->create(self::string($options->getContent())),
            'name' => 'The key of a first day',
        ]);
    }
}
