<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0025
 */
final class AFirstPasskeyFromATicketTest extends PasskeyTestCase
{
    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
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
     * @return IssuedTicket<EnrolmentTicket>
     */
    private function issue(): IssuedTicket
    {
        $alice = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($this->alice->id) ?? static::fail('The person is gone.');
        $issued = self::service('test.beffroi.enrolment_tickets', EnrolmentTicketIssue::class)->issue($alice, self::context());
        self::forgetEvents();

        return $issued;
    }

    /**
     * @param IssuedTicket<EnrolmentTicket> $issued
     */
    private function path(IssuedTicket $issued): string
    {
        return '/enrol/' . $issued->ticket->id->toRfc4122() . '/' . $issued->value;
    }

    /**
     * @param IssuedTicket<EnrolmentTicket> $issued
     */
    private function ticketPage(IssuedTicket $issued): Crawler
    {
        $crawler = $this->browser->request('GET', $this->path($issued));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * @param IssuedTicket<EnrolmentTicket> $issued
     */
    private function poseAPasskey(IssuedTicket $issued, SoftwareAuthenticator $device): void
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
