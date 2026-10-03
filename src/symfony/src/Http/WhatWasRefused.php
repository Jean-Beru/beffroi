<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function is_array;
use function is_string;
use Symfony\Component\HttpFoundation\Request;

/**
 * What carries a refusal across the redirection every form of these pages answers with (issue #481).
 *
 * **Every form answers with a redirection**, accepted or refused, so that a browser reloading the page it
 * came back to does not post the form again (POST, redirect, GET). A refusal has nowhere to live across a
 * redirection but the session of that browser, so it lives there, for the one read that follows: the page
 * takes it and it is gone, which is why reloading that page a second time shows no refusal.
 *
 * It is the session of the browser and not a cookie: a cookie travels to every request of this host and is
 * written by whoever holds the browser, where this is read once by the page that was redirected to.
 */
final readonly class WhatWasRefused
{
    public const string KEY = 'beffroi.refusal';

    /**
     * @param string $code a code the page translates
     * @param string|null $field what the refusal is about, when it is about one field of several
     */
    public function keep(Request $request, string $code, ?string $field = null): void
    {
        $request->getSession()->set(self::KEY, [
            'code' => $code,
            'field' => $field,
        ]);
    }

    /**
     * The refusal the request before this one left, and nothing on the next read: a page shows what was
     * refused once, where a reload of it shows the page as it is.
     */
    public function take(Request $request): ?Refusal
    {
        if (! $request->hasSession()) {
            return null;
        }
        $session = $request->getSession();
        $kept = $session->get(self::KEY);
        $session->remove(self::KEY);
        if (! is_array($kept) || ! is_string($kept['code'] ?? null)) {
            return null;
        }
        $field = $kept['field'] ?? null;

        return new Refusal($kept['code'], is_string($field) ? $field : null);
    }
}
