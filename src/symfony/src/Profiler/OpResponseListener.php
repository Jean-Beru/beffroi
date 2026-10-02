<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use function is_array;
use function json_decode;
use JsonException;
use const JSON_THROW_ON_ERROR;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * What a protocol endpoint answered, member by member: the tokens of RFC 6749 §5.1, the claims of
 * UserInfo (OIDC Core §5.3.2), the members of an introspection (RFC 7662 §2.2), the error of a refusal
 * (RFC 6749 §5.2). This is the other half of what stops being readable once a request is signed and a
 * token is bound: a client reads the body, the provider writes it, and nobody watching from outside
 * sees either.
 *
 * No value that is a credential leaves this listener. An answer the provider signed or encrypted for
 * its client is not opened here: it left as one string, it is shown as one string that is there, and
 * what went into it is said by the issuer that wrote it.
 */
#[AsEventListener(event: KernelEvents::RESPONSE, priority: self::PRIORITY)]
final readonly class OpResponseListener
{
    /**
     * Above the profiler, which collects at -100.
     */
    public const int PRIORITY = 0;

    public function __construct(
        private OpProfile $profile,
        private PanelValues $values,
    ) {
    }

    public function __invoke(ResponseEvent $event): void
    {
        $response = $event->getResponse();
        if (! $event->isMainRequest() || ! $this->profile->hasTouchedTheProvider()) {
            return;
        }
        $this->profile->record(new Observation('Response', 'Answer', [
            'status' => (string) $response->getStatusCode(),
            'content type' => $response->headers->get('Content-Type') ?? 'none',
            'body' => $this->body($response),
        ]));
    }

    private function body(Response $response): string
    {
        $content = $response->getContent();
        if ($content === false || $content === '') {
            return 'empty';
        }
        try {
            $members = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return 'not JSON: a page, a redirection or a document signed for the client';
        }
        if (! is_array($members)) {
            return 'JSON that is not an object';
        }
        return $this->values->all($members, 'an empty object');
    }
}
