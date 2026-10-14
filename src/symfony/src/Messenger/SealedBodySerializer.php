<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Messenger;

use __PHP_Incomplete_Class;
use function array_map;
use function array_values;
use function base64_decode;
use function base64_encode;
use Beffroi\Core\Exception\InvalidJweException;
use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Core\Port\MessageBodyOpenerInterface;
use Beffroi\Core\Port\MessageBodySealerInterface;
use function is_array;
use function is_object;
use function is_string;
use function serialize;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Exception\MessageDecodingFailedException;
use Symfony\Component\Messenger\Stamp\HandledStamp;
use Symfony\Component\Messenger\Stamp\NonSendableStampInterface;
use Symfony\Component\Messenger\Stamp\StampInterface;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
use Throwable;
use function unserialize;

/**
 * What this provider writes to a transport, sealed (decision 0020): the body is a JWE to the message key
 * of the tenant, so what a broker keeps on its disk, and what the table of a transport holds, is worth
 * nothing without the KMS, exactly as a column is at rest (decision 0011).
 *
 * **In place of the default serializer of Messenger**, which puts the whole envelope, stamps included, in
 * the body: this one separates the two. The body is `serialize($message)` under the seal, which asks
 * nothing new of a message that the default serializer did not already ask (the suites of both packages
 * write every event of theirs to a queue and read it back); the stamps go in headers, one per class, the
 * way the serializer of the component writes them (`X-Message-Stamp-<FQCN>`).
 *
 * **What stays in the clear is what makes a failed message readable**, and it is named rather than
 * discovered: the class of the message, the stamps, and the scope it was written under (TenantStamp). So
 * `messenger:failed:show` names a message, dates it and explains it without the body being opened, which
 * is what an operator needs of a failure whose scope is gone. Nothing of a person is among them.
 *
 * **A header decides nothing.** The scope is sealed with the body, so a header moved by whoever can write
 * to a transport makes the opening fail instead of opening somewhere else. Reading the stamps back
 * instantiates what a header names, which is the exposure the default serializer has today for the whole
 * envelope: it is why what decides is in the body and never here, and why a stamp that comes back as
 * anything other than what its header names is refused.
 */
final readonly class SealedBodySerializer implements SerializerInterface
{
    /**
     * One header per class of stamp, as the serializer of the component names them.
     */
    public const string STAMP_HEADER_PREFIX = 'X-Message-Stamp-';

    /**
     * The class of the message, which names a failed one without its body being opened.
     */
    public const string TYPE_HEADER = 'type';

    public function __construct(
        private AmbientTenantInterface $tenants,
        private MessageBodySealerInterface $sealer,
        private MessageBodyOpenerInterface $opener,
    ) {
    }

    public function encode(Envelope $envelope): array
    {
        $message = $envelope->getMessage();
        // A body that failed to decode goes on as it arrived: it is already sealed, and its headers
        // describe it. Sealing the exception instead would put a body nobody can read behind a type
        // nobody expects, and the failure transport is where an operator looks.
        $failed = self::bodyThatFailedToDecode($message);
        $envelope = $envelope->withoutStampsOfType(NonSendableStampInterface::class);
        // handler results are for synchronous callers: a retry needs the names of the handlers that ran
        $handled = $envelope->all(HandledStamp::class);
        if ($handled !== []) {
            $envelope = $envelope
                ->withoutAll(HandledStamp::class)
                ->with(...array_map(
                    static fn (HandledStamp $stamp): HandledStamp => new HandledStamp(null, $stamp->getHandlerName()),
                    $handled,
                ));
        }
        if ($failed !== null) {
            $headers = [
                self::TYPE_HEADER => $failed['headers'][self::TYPE_HEADER] ?? $message::class,
                ...self::encodeStamps($envelope),
            ];

            return [
                'body' => $failed['body'],
                'headers' => $headers + $failed['headers'],
            ];
        }
        $tenant = $this->tenants->provide();
        $envelope = $envelope->withoutAll(TenantStamp::class)->with(new TenantStamp($tenant->slug));

        return [
            'body' => $this->sealer->seal($tenant, serialize($message)),
            'headers' => [
                self::TYPE_HEADER => $message::class,
                ...self::encodeStamps($envelope),
            ],
        ];
    }

    /**
     * A body that does not open is a failure of this message and not of the process, so it comes back as
     * the envelope the component expects, which the worker routes to the failure transport with the
     * headers it arrived with.
     *
     * A KMS that does not answer is the other way round and is left to pass: the message is good, the
     * process is not, and a message sent to the failure transport because a KMS was down is a message
     * nobody will replay. The same holds for a process that has no tenant.
     */
    public function decode(array $encodedEnvelope): Envelope
    {
        $stamps = self::decodeStamps($encodedEnvelope, $stampFailure);
        $body = $encodedEnvelope['body'];
        if ($body === '') {
            return MessageDecodingFailedException::wrap($encodedEnvelope, 'An encoded envelope of this provider carries a sealed body.')->with(...$stamps);
        }
        if ($stampFailure !== null) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, $stampFailure->getMessage(), 0, $stampFailure)->with(...$stamps);
        }
        $scope = self::scope($stamps);
        if ($scope === null) {
            return MessageDecodingFailedException::wrap(
                $encodedEnvelope,
                'An encoded envelope of this provider names the tenant it was written for.',
            )->with(...$stamps);
        }
        $tenant = $this->tenants->provide();
        if ($scope !== $tenant->slug) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, sprintf(
                'The message was written for the tenant "%s" and this process serves "%s".',
                $scope,
                $tenant->slug,
            ))->with(...$stamps);
        }
        try {
            $opened = $this->opener->open($tenant, $body);
        } catch (InvalidJweException $exception) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, $exception->getMessage(), 0, $exception)->with(...$stamps);
        }
        $message = self::read($opened);
        if ($message === null) {
            return MessageDecodingFailedException::wrap(
                $encodedEnvelope,
                'The body of the message does not read back as the message it carried.',
            )->with(...$stamps);
        }
        $type = self::headers($encodedEnvelope)[self::TYPE_HEADER] ?? null;
        if ($type !== $message::class) {
            return MessageDecodingFailedException::wrap($encodedEnvelope, sprintf(
                'The body of the message opens as "%s" and its headers name "%s".',
                $message::class,
                is_string($type) ? $type : 'nothing',
            ))->with(...$stamps);
        }

        return new Envelope($message, $stamps);
    }

    /**
     * @return array{body: string, headers: array<string, string>}|null
     */
    private static function bodyThatFailedToDecode(object $message): ?array
    {
        if (! $message instanceof MessageDecodingFailedException) {
            return null;
        }
        $encoded = $message->encodedEnvelope;
        $body = $encoded['body'] ?? null;
        if (! is_string($body) || $body === '') {
            return null;
        }
        $headers = [];
        foreach (is_array($encoded['headers'] ?? null) ? $encoded['headers'] : [] as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $headers[$name] = $value;
            }
        }

        return [
            'body' => $body,
            'headers' => $headers,
        ];
    }

    /**
     * @return array<string, string>
     */
    private static function encodeStamps(Envelope $envelope): array
    {
        $headers = [];
        foreach ($envelope->all() as $class => $stamps) {
            $headers[self::STAMP_HEADER_PREFIX . $class] = base64_encode(serialize(array_values($stamps)));
        }

        return $headers;
    }

    /**
     * The stamps that read back, and what went wrong with the first one that did not: a failure keeps the
     * stamps it could read, so that the retries of a message are still counted.
     *
     * @param array{body?: string, headers?: array<string, string>, extra?: array<string, mixed>} $encodedEnvelope
     *
     * @return list<StampInterface>
     */
    private static function decodeStamps(array $encodedEnvelope, ?Throwable &$failure = null): array
    {
        $stamps = [];
        foreach (self::headers($encodedEnvelope) as $name => $value) {
            if (! str_starts_with($name, self::STAMP_HEADER_PREFIX)) {
                continue;
            }
            $class = substr($name, strlen(self::STAMP_HEADER_PREFIX));
            $decoded = base64_decode($value, true);
            $read = $decoded === false
                ? false
                : @unserialize($decoded, [
                    'allowed_classes' => true,
                ]);
            if (! is_array($read)) {
                $failure ??= new MessageDecodingFailedException(sprintf('The header of the stamp "%s" does not read back.', $class));

                continue;
            }
            foreach ($read as $stamp) {
                if (! $stamp instanceof StampInterface || $stamp::class !== $class) {
                    $failure ??= new MessageDecodingFailedException(sprintf('The header of the stamp "%s" carries something else.', $class));

                    continue;
                }
                $stamps[] = $stamp;
            }
        }

        return $stamps;
    }

    /**
     * The headers of an encoded envelope, the ones that are a string under a string: what a transport
     * carried is whatever it carried, and nothing here reads a header it cannot read twice.
     *
     * @param array{body?: string, headers?: array<string, string>, extra?: array<string, mixed>} $encodedEnvelope
     *
     * @return array<string, string>
     */
    private static function headers(array $encodedEnvelope): array
    {
        $headers = [];
        foreach (is_array($encodedEnvelope['headers'] ?? null) ? $encodedEnvelope['headers'] : [] as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $headers[$name] = $value;
            }
        }

        return $headers;
    }

    /**
     * @param list<StampInterface> $stamps
     */
    private static function scope(array $stamps): ?string
    {
        $scope = null;
        foreach ($stamps as $stamp) {
            if ($stamp instanceof TenantStamp) {
                $scope = $stamp->slug;
            }
        }

        return $scope;
    }

    /**
     * The message the opened body carried. A class this process does not have comes back incomplete, and
     * anything that is not an object is not a message: both are a body that does not read back rather than
     * a message handed to a bus.
     */
    private static function read(string $opened): ?object
    {
        $message = @unserialize($opened, [
            'allowed_classes' => true,
        ]);

        return is_object($message) && ! $message instanceof __PHP_Incomplete_Class ? $message : null;
    }
}
