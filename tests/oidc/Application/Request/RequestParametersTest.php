<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Request;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Exception\InvalidRequestException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6749 §3.1, read the one way every endpoint reads it: a parameter without a value is omitted, a
 * repeated or nested one is refused rather than reduced to one, and whether a failure may be redirected
 * back to the client is said once, by the stage that takes the parameters up.
 */
final class RequestParametersTest extends TestCase
{
    #[Test]
    public function itReadsAParameterWithAValue(): void
    {
        // Given
        $request = RequestParameters::of([
            'grant_type' => 'authorization_code',
        ]);

        // When / Then
        static::assertSame('authorization_code', $request->optional('grant_type'));
    }

    #[Test]
    public function aRequiredParameterWithAValueIsRead(): void
    {
        // Given
        $request = RequestParameters::of([
            'grant_type' => 'authorization_code',
        ]);

        // When / Then
        static::assertSame('authorization_code', $request->required('grant_type'));
    }

    /**
     * RFC 6749 §3.1: a parameter sent without a value is a parameter that was not sent.
     */
    #[Test]
    #[DataProvider('provideOmittedParameters')]
    public function anOptionalParameterWithoutAValueIsNull(string $name): void
    {
        // Given
        $request = RequestParameters::of(self::sent());

        // When / Then
        static::assertNull($request->optional($name));
    }

    #[Test]
    #[DataProvider('provideOmittedParameters')]
    public function aRequiredParameterWithoutAValueIsMissing(string $name): void
    {
        // Given
        $request = RequestParameters::of(self::sent());

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The ' . $name . ' parameter is missing.');

        // When
        $request->required($name);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOmittedParameters(): iterable
    {
        yield 'empty' => ['code'];
        yield 'absent' => ['redirect_uri'];
    }

    #[Test]
    public function aParameterWithoutAValueIsNotPresent(): void
    {
        // Given
        $request = RequestParameters::of(self::sent());

        // When / Then
        static::assertFalse($request->isPresent('code'));
    }

    #[Test]
    public function aParameterWithAValueIsPresent(): void
    {
        // Given
        $request = RequestParameters::of(self::sent());

        // When / Then
        static::assertTrue($request->isPresent('grant_type'));
    }

    /**
     * RFC 6749 §3.1: a parameter the specification says is single is refused when it is sent twice,
     * whichever of the two ways it is read.
     *
     * @param callable(RequestParameters): mixed $read
     */
    #[Test]
    #[DataProvider('provideSingleReads')]
    public function aRepeatedParameterIsRefused(callable $read): void
    {
        // Given
        $request = RequestParameters::of(self::sent());

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The scope parameter must be a single string.');

        // When
        $read($request);
    }

    /**
     * @return iterable<string, array{callable(RequestParameters): mixed}>
     */
    public static function provideSingleReads(): iterable
    {
        yield 'optional' => [static fn (RequestParameters $request): ?string => $request->optional('scope')];
        yield 'required' => [static fn (RequestParameters $request): string => $request->required('scope')];
    }

    /**
     * RFC 6749 §4.1.2.1: the first stage of an authorization request knows no redirect URI yet, and the
     * endpoints that answer in JSON never redirect at all.
     */
    #[Test]
    public function aFailureIsNotRedirectableByDefault(): void
    {
        // Given
        $request = RequestParameters::of(self::sent());

        // When
        try {
            $request->required('response_type');
            static::fail('The parameter is missing.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertFalse($exception->redirectable);
        }
    }

    /**
     * RFC 6749 §4.1.2.1: the stage that answers to the client says so once, and every rule it reads
     * with refuses the way that stage refuses.
     */
    #[Test]
    public function aFailureOfAStageThatAnswersToTheClientIsRedirectable(): void
    {
        // Given
        $request = RequestParameters::of(self::sent())->withRedirectableFailures();

        // When
        try {
            $request->required('response_type');
            static::fail('The parameter is missing.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * RFC 6749 §4.1.1: where an answer may go is read off the client, so a request that names none is
     * refused on the spot whatever the stage that reads it.
     */
    #[Test]
    public function aMissingClientIdIsNeverRedirectable(): void
    {
        // Given
        $request = RequestParameters::of([])->withRedirectableFailures();

        // When
        try {
            $request->clientId();
            static::fail('The client_id parameter is missing.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertSame('The client_id parameter is missing.', $exception->errorDescription);
            static::assertFalse($exception->redirectable);
        }
    }

    #[Test]
    public function itReadsTheClientThatNamesItself(): void
    {
        // Given
        $request = RequestParameters::of([
            'client_id' => 'demo',
        ]);

        // When / Then
        static::assertSame('demo', $request->clientId());
    }

    /**
     * RFC 8707 §2: the one kind of parameter a specification allows to be sent several times, read as
     * the list it is, in the order it came and without repeats.
     *
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideRepeatedValues')]
    public function aParameterASpecificationAllowsToRepeatIsReadAsAList(mixed $value, array $expected): void
    {
        // Given
        $request = RequestParameters::of([
            'resource' => $value,
        ]);

        // When / Then
        static::assertSame($expected, $request->repeated('resource'));
    }

    /**
     * @return iterable<string, array{mixed, list<string>}>
     */
    public static function provideRepeatedValues(): iterable
    {
        yield 'absent' => ['', []];
        yield 'an empty list' => [[], []];
        yield 'sent once' => ['https://api.example', ['https://api.example']];
        yield 'sent twice' => [
            ['https://api.example', 'https://files.example'],
            ['https://api.example', 'https://files.example'],
        ];
        yield 'sent twice with the same value' => [['https://api.example', 'https://api.example'], ['https://api.example']];
    }

    #[Test]
    #[DataProvider('provideMalformedRepeatedValues')]
    public function aRepeatableParameterThatIsNeitherAStringNorAListOfThemIsRefused(mixed $value): void
    {
        // Given
        $request = RequestParameters::of([
            'resource' => $value,
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The resource parameter must be a string or a list of strings.');

        // When
        $request->repeated('resource');
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideMalformedRepeatedValues(): iterable
    {
        yield 'nested' => [[
            'one' => 'https://api.example',
        ]];
        yield 'a list with an empty value' => [['https://api.example', '']];
        yield 'a list with something that is not a string' => [['https://api.example', ['https://files.example']]];
    }

    /**
     * RFC 6749 appendix A.5: state = 1*VSCHAR.
     */
    #[Test]
    public function aStateThatIsNotPrintableAsciiIsRefused(): void
    {
        // Given
        $request = RequestParameters::of([
            'state' => "the\nstate",
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The state parameter must be printable ASCII text (RFC 6749 appendix A.5).');

        // When
        $request->state();
    }

    #[Test]
    public function itReadsAPrintableState(): void
    {
        // Given
        $request = RequestParameters::of([
            'state' => 'af0ifjsldkj',
        ]);

        // When / Then
        static::assertSame('af0ifjsldkj', $request->state());
    }

    #[Test]
    public function textWithAControlCharacterIsRefused(): void
    {
        // Given
        $request = RequestParameters::of([
            'nonce' => "n-0S6_\0WzA2Mj",
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The nonce parameter must be text without control characters.');

        // When
        $request->text('nonce');
    }

    /**
     * RFC 7515 §7.1, OIDC Core §2: three segments, none of them empty.
     */
    #[Test]
    public function aValueThatIsNotACompactJwsIsRefused(): void
    {
        // Given
        $request = RequestParameters::of([
            'id_token_hint' => 'header.payload',
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The id_token_hint parameter is not a signed compact JWT.');

        // When
        $request->compactJws('id_token_hint');
    }

    /**
     * OIDC Core §3.1.2.1 "ui_locales": space-separated language tags, most preferred first, kept once
     * each.
     */
    #[Test]
    public function itReadsTheLanguageTagsInTheOrderTheyWereAskedFor(): void
    {
        // Given
        $request = RequestParameters::of([
            'ui_locales' => 'fr-CA fr en fr',
        ]);

        // When / Then
        static::assertSame(['fr-CA', 'fr', 'en'], $request->uiLocales());
    }

    #[Test]
    public function aValueThatIsNotALanguageTagIsRefused(): void
    {
        // Given
        $request = RequestParameters::of([
            'ui_locales' => 'fr *',
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The ui_locales parameter must be a space-separated list of language tags.');

        // When
        $request->uiLocales();
    }

    /**
     * @return array<string, mixed> what a client sent: one parameter with a value, one empty, one twice
     */
    private static function sent(): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => '',
            'scope' => ['openid', 'profile'],
        ];
    }
}
