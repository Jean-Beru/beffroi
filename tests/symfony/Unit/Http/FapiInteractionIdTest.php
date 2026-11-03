<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\FapiInteractionId;
use App\Http\ServesAProtectedResourceInterface;
use Beffroi\Core\Bridge\Uid\FixedUuidGenerator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Uid\Uuid;

/**
 * FAPI 1.0 Advanced Final §6.2.1: the answer of a protected resource of the provider names the exchange
 * it belongs to, with the UUID the request named or with one drawn for it, and the answer of anything
 * else names none.
 */
final class FapiInteractionIdTest extends TestCase
{
    /**
     * What a client names an exchange with: the UUID §6.2.1 asks it to send.
     */
    private const string NAMED = '9f4ecb8a-0a4a-4a8f-9b06-77b5b0d1a2c3';

    /**
     * What the provider draws for a request that named nothing it could read.
     */
    private const string DRAWN = '3d1b4b24-6a2a-4df1-9f8f-2c1b60cb7c11';

    /**
     * A second UUID, for the request that names the header twice.
     */
    private const string ALSO_NAMED = '5c2d9f70-1e84-4f16-8a42-0b0d3f7e6a55';

    #[Test]
    public function theAnswerOfAResourceCarriesTheUuidTheRequestNamed(): void
    {
        // Given
        $request = self::request([self::NAMED]);

        // When
        $response = self::answerOfAResourceTo($request);

        // Then
        static::assertSame(self::NAMED, $response->headers->get(FapiInteractionId::HEADER));
    }

    #[Test]
    public function theAnswerOfAResourceToARequestThatNamedNoneCarriesOneDrawnForIt(): void
    {
        // Given
        $request = self::request([]);

        // When
        $response = self::answerOfAResourceTo($request);

        // Then
        static::assertSame(self::DRAWN, $response->headers->get(FapiInteractionId::HEADER));
    }

    /**
     * §6.2.1 asks the client for an RFC 4122 UUID, so anything else names no exchange on either side and
     * is not echoed; a request naming the header twice has named it once too often.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function provideWhatNamesNoExchange(): iterable
    {
        yield 'an empty value' => [['']];
        yield 'a word' => [['the-one-before']];
        yield 'a UUID missing a group' => [['9f4ecb8a-0a4a-4a8f-77b5b0d1a2c3']];
        yield 'a variant RFC 4122 does not define' => [['9f4ecb8a-0a4a-4a8f-fb06-77b5b0d1a2c3']];
        yield 'the header twice' => [[self::NAMED, self::ALSO_NAMED]];
    }

    /**
     * @param list<string> $named
     */
    #[Test]
    #[DataProvider('provideWhatNamesNoExchange')]
    public function theAnswerOfAResourceCarriesOneDrawnForARequestThatNamedNothingReadable(array $named): void
    {
        // Given
        $request = self::request($named);

        // When
        $response = self::answerOfAResourceTo($request);

        // Then
        static::assertSame(self::DRAWN, $response->headers->get(FapiInteractionId::HEADER));
    }

    /**
     * The header is owed by the resources of the provider and by nothing else: an endpoint a client
     * authenticates at and a page a browser reaches carry none, whatever the request named.
     */
    #[Test]
    public function theAnswerOfWhatIsNoResourceCarriesNothing(): void
    {
        // Given
        $listener = self::listener();
        $request = self::request([self::NAMED]);
        $controller = new class() {
            public function __invoke(): Response
            {
                return new Response();
            }
        };

        // When
        $response = self::answer($listener, $request, $controller);

        // Then
        static::assertFalse($response->headers->has(FapiInteractionId::HEADER));
    }

    private static function listener(): FapiInteractionId
    {
        return new FapiInteractionId(new FixedUuidGenerator([Uuid::fromString(self::DRAWN)]));
    }

    /**
     * @param list<string> $named what the request carries under the header, as many times as it carries it
     */
    private static function request(array $named): Request
    {
        $request = Request::create('/userinfo');
        foreach ($named as $value) {
            $request->headers->set(FapiInteractionId::HEADER, $value, false);
        }

        return $request;
    }

    private static function answerOfAResourceTo(Request $request): Response
    {
        $controller = new class() implements ServesAProtectedResourceInterface {
            public function __invoke(): Response
            {
                return new Response();
            }
        };

        return self::answer(self::listener(), $request, $controller);
    }

    private static function answer(FapiInteractionId $listener, Request $request, callable $controller): Response
    {
        $kernel = static::createStub(HttpKernelInterface::class);
        $listener->onKernelController(new ControllerEvent($kernel, $controller, $request, HttpKernelInterface::MAIN_REQUEST));
        $response = new Response();
        $listener->onKernelResponse(new ResponseEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST, $response));

        return $response;
    }
}
