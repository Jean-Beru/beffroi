<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Key;

use Beffroi\Bundle\Key\KmsUnavailableListener;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\KeyManagement\Exception\RuntimeException as KeyManagementRuntimeException;
use Throwable;

/**
 * Issue #128, architecture §3.3 and §5.4: what the listener of the bundle makes of an exception on its way
 * out of a request, on the real ExceptionEvent of the kernel; the requests themselves are KmsOutageTest.
 */
final class KmsUnavailableListenerTest extends DatabaseTestCase
{
    private KmsUnavailableListener $listener;

    protected function setUp(): void
    {
        parent::setUp();
        $this->listener = self::service('test.beffroi.kms_unavailable_listener', KmsUnavailableListener::class);
    }

    #[Test]
    public function anOutageOfTheKmsBecomesAServiceUnavailableWithARetryAfter(): void
    {
        // Given
        $outage = self::outage();
        $event = self::event($outage);

        // When
        ($this->listener)($event);

        // Then
        $throwable = $event->getThrowable();
        static::assertInstanceOf(ServiceUnavailableHttpException::class, $throwable);
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $throwable->getStatusCode());
        static::assertSame(
            [
                'Retry-After' => KmsUnavailableListener::RETRY_AFTER,
            ],
            $throwable->getHeaders(),
        );
        static::assertSame($outage, $throwable->getPrevious());
    }

    /**
     * What wrapped the outage on its way up (a bus, a handler) does not hide it.
     */
    #[Test]
    public function anOutageWrappedOnItsWayUpIsStillAnOutage(): void
    {
        // Given
        $wrapped = new RuntimeException('Handling failed.', 0, self::outage());
        $event = self::event($wrapped);

        // When
        ($this->listener)($event);

        // Then
        $throwable = $event->getThrowable();
        static::assertInstanceOf(ServiceUnavailableHttpException::class, $throwable);
        static::assertSame($wrapped, $throwable->getPrevious());
    }

    /**
     * Architecture §3.5: the audit receives the outage with the request it turned away and the words of
     * the KMS.
     */
    #[Test]
    public function theOutageIsAnnouncedWithTheRequestAndTheWordsOfTheKms(): void
    {
        // Given
        $event = self::event(self::outage());

        // When
        ($this->listener)($event);

        // Then
        $announced = self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events;
        static::assertCount(1, $announced);
        static::assertInstanceOf(KmsUnavailable::class, $announced[0]);
        static::assertSame('The sealed secret could not be opened. Failed to reach Vault. Could not resolve host: vault', $announced[0]->reason);
        static::assertSame('203.0.113.7', $announced[0]->context->ipAddress);
        static::assertSame('Mozilla/5.0 (test)', $announced[0]->context->userAgent);
        static::assertTrue($announced[0]->tenant->equals(self::tenant()));
    }

    #[Test]
    public function anotherFailureIsLeftAloneAndAnnouncesNothing(): void
    {
        // Given
        $failure = new RuntimeException('The sealed secret could not be opened.');
        $event = self::event($failure);

        // When
        ($this->listener)($event);

        // Then
        static::assertSame($failure, $event->getThrowable());
        static::assertSame([], self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events);
    }

    /**
     * What the sealer throws when the bridge of Vault cannot reach it, with the words of the bridge and of
     * the transport under it.
     */
    private static function outage(): KmsUnavailableException
    {
        return new KmsUnavailableException(
            'The sealed secret could not be opened.',
            0,
            new KeyManagementRuntimeException('Failed to reach Vault.', 0, new \RuntimeException("Could not resolve host:\n vault")),
        );
    }

    private static function event(Throwable $throwable): ExceptionEvent
    {
        $request = Request::create('/login/code', 'POST', server: [
            'REMOTE_ADDR' => '203.0.113.7',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (test)',
        ]);

        return new ExceptionEvent(self::service('kernel', HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST, $throwable);
    }
}
