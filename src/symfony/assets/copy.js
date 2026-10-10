/*
 * What a page of the account asks the browser to do for the person reading it: put what the page is
 * showing them into their clipboard (Clipboard API §3). It is for the one page that shows something
 * nobody can be asked to copy by hand: the backup codes of a second factor, shown once, ten of them, and
 * one mistyped is one that will not sign anybody in.
 *
 * The button is hidden until this script finds a browser that can write a clipboard, so a browser that
 * cannot is never shown a button that does nothing. The codes are on the page either way, as text
 * somebody selects: this adds a way and replaces none.
 *
 * Nothing is loaded from anywhere else and nothing is sent anywhere. What is copied is what the page
 * already shows: the script reads the element the button names and holds no value of its own.
 */
(() => {
    'use strict';

    const button = document.querySelector('button[data-copy]');
    if (!button || !navigator.clipboard) {
        return;
    }
    const copies = document.getElementById(button.dataset.copy);
    if (!copies) {
        return;
    }

    const done = document.querySelector('[data-copied]');
    const refused = document.querySelector('[data-copy-refused]');

    button.hidden = false;
    button.addEventListener('click', async () => {
        /* One line per item, which is what somebody pastes into the file where they keep them. */
        const lines = Array.from(copies.querySelectorAll('code'), (code) => (code.textContent ?? '').trim());
        try {
            await navigator.clipboard.writeText(lines.join('\n'));
            if (done) {
                done.hidden = false;
            }
            if (refused) {
                refused.hidden = true;
            }
        } catch (error) {
            /* A browser that refuses the clipboard says so where the page says everything else, and the
               codes stay where they are. */
            if (refused) {
                refused.hidden = false;
            }
            if (done) {
                done.hidden = true;
            }
        }
    });
})();
