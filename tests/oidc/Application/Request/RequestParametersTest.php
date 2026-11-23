<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Request;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Exception\InvalidRequestException;
use function array_fill;
use function array_map;
use function implode;
use function range;
use function sprintf;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6749 §3.1
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
     * RFC 6749 §3.1
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
     * RFC 6749 §3.1
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
     * RFC 6749 §4.1.2.1
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
     * RFC 6749 §4.1.2.1
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
     * RFC 6749 §4.1.1
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
     * RFC 8707 §2
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
        yield 'values made of digits' => [['2', '1', '02', '2'], ['2', '1', '02']];
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aRepeatedParameterOfAHundredValuesIsRead(): void
    {
        // Given
        $request = RequestParameters::of([
            'resource' => self::resources(100),
        ]);

        // When / Then
        static::assertCount(100, $request->repeated('resource'));
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aRepeatedParameterOfMoreThanAHundredValuesIsRefused(): void
    {
        // Given
        $request = RequestParameters::of([
            'resource' => self::resources(101),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The resource parameter holds 100 values at most.');

        // When
        $request->repeated('resource');
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
     * RFC 6749 appendix A.5
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
     * RFC 7515 §7.1, OIDC Core §2
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
     * OIDC Core §3.1.2.1
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

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itReadsTheAuthenticationContextClassesOnceInTheOrderTheyWereAskedFor(): void
    {
        // Given
        $request = RequestParameters::of([
            'acr_values' => '2 1 02 2 1',
        ]);

        // When / Then
        static::assertSame(['2', '1', '02'], $request->acrValues());
    }

    /**
     * OIDC Core §3.1.2.1
     *
     * @param callable(RequestParameters): list<string> $read
     */
    #[Test]
    #[DataProvider('provideSpaceSeparatedLists')]
    public function aListOfAHundredValuesIsRead(string $name, callable $read): void
    {
        // Given
        $request = RequestParameters::of([
            $name => implode(' ', array_map(static fn (int $index): string => 'en-' . $index, range(1, 100))),
        ]);

        // When / Then
        static::assertCount(100, $read($request));
    }

    /**
     * OIDC Core §3.1.2.1
     *
     * @param callable(RequestParameters): list<string> $read
     */
    #[Test]
    #[DataProvider('provideSpaceSeparatedLists')]
    public function aListOfMoreThanAHundredValuesIsRefusedBeforeAnyIsRead(string $name, callable $read): void
    {
        // Given
        $request = RequestParameters::of([
            $name => implode(' ', array_fill(0, 101, "\u{e9}")),
        ]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs(sprintf('invalid_request: The %s parameter holds 100 values at most.', $name));

        // When
        $read($request);
    }

    /**
     * @return iterable<string, array{string, callable(RequestParameters): list<string>}>
     */
    public static function provideSpaceSeparatedLists(): iterable
    {
        yield 'ui_locales' => ['ui_locales', static fn (RequestParameters $request): array => $request->uiLocales()];
        yield 'acr_values' => ['acr_values', static fn (RequestParameters $request): array => $request->acrValues()];
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
     * @return list<string>
     */
    private static function resources(int $count): array
    {
        return array_map(static fn (int $index): string => 'https://api.example/' . $index, range(1, $count));
    }

    /**
     * @return array<string, mixed>
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
