// The browser of "castor conformance" for one module of the OpenID conformance suite that asks for a capture
// of a page of the OP (tests/conformance/README.md, "The captures"). It visits each URL the suite publishes
// for the module, answers the pages of the OP as the "browser" section of configuration.json does, captures
// the page captures.json names for the module, sends the capture to the placeholder the module opened, and
// fails on what that page must be and is not.
//
//   node capture.mjs <plan> <module> <id of the module in the suite>
//
// BEFFROI_ISSUER, BEFFROI_DEV_USERNAME, BEFFROI_DEV_USER_PASSWORD and CONFORMANCE_SUITE (the suite as the
// browser reaches it) come from "castor conformance"; CONFORMANCE_SUITE_API (the suite as this container
// reaches it) and CONFORMANCE_BROWSER_RESOLVER_RULES from compose.yaml; CONFORMANCE_TOKEN from the
// environment of a hosted suite. The PNG is written to /captures/<plan>/<module>.png, beside a JSON report.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { chromium, request } from 'playwright-core';

const PAGES = {
    // RFC 6749 §3.1.2.4, RP-Initiated Logout 1.0 §3 and §4: the error is shown, the redirection never happens.
    refusal: { shows: 'p[data-error]', status: 400, ends: true },
    // OIDC Core §3.1.2.1, prompt=login.
    'sign-in-again': { shows: '[data-requirement=reauthentication_requested]', status: 200, ends: false },
    // OIDC Core §3.1.2.1, max_age.
    'sign-in-past-max-age': { shows: '[data-requirement=max_age_exceeded]', status: 200, ends: false },
    // OIDC Registration §2: what a client registered about itself, which this OP shows on its consent page.
    'client-logo': { shows: 'img[data-client=logo]', status: 200, ends: true },
    'client-policy': { shows: 'a[data-client=policy_uri]', status: 200, ends: true },
    'client-terms': { shows: 'a[data-client=tos_uri]', status: 200, ends: true },
    'signed-out': { shows: '[data-logged-out=yes]', status: 200, ends: true },
    // RP-Initiated Logout 1.0 §2: the OP asks when the ID Token does not belong to the current session.
    'logout-question': { shows: 'button[name=confirm][value=yes]', status: 200, ends: true },
};

const MODULE_SECONDS = 120;
// How long a module may wait with no URL left to visit before the page it asks for is taken as never coming.
const QUIET_SECONDS = 15;
const PLACEHOLDER_SECONDS = 5;
// What is watched after a capture on a page a module ends on, for a redirection the OP must not make.
const STILL_SECONDS = 2;
const STEPS = 12;

class Failed extends Error {}

const [plan, module, id] = process.argv.slice(2);
const env = process.env;
for (const name of ['BEFFROI_ISSUER', 'BEFFROI_DEV_USERNAME', 'BEFFROI_DEV_USER_PASSWORD', 'CONFORMANCE_SUITE']) {
    if (!env[name]) {
        console.error(`${name} is not set.`);
        process.exit(2);
    }
}
const pageName = JSON.parse(readFileSync(new URL('./captures.json', import.meta.url), 'utf8'))[module];
if (plan === undefined || id === undefined || pageName === undefined) {
    console.error('usage: node capture.mjs <plan> <module of captures.json> <id of the module>');
    process.exit(2);
}
const expected = PAGES[pageName];
const issuer = new URL(env.BEFFROI_ISSUER).origin;
const suiteOrigin = new URL(env.CONFORMANCE_SUITE).origin;
const directory = `/captures/${plan}`;
const trail = [];
const captures = [];

const say = (line) => {
    trail.push(line);
    console.log(line);
};

const suite = await request.newContext({
    baseURL: env.CONFORMANCE_SUITE_API || env.CONFORMANCE_SUITE,
    // The suite of "castor start --conformance" serves a self-signed certificate.
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: env.CONFORMANCE_TOKEN ? { Authorization: `Bearer ${env.CONFORMANCE_TOKEN}` } : {},
});

async function api(method, path, { type = 'application/json', body = '' } = {}) {
    const response = await suite.fetch(path, { method, headers: { 'Content-Type': type }, data: method === 'GET' ? undefined : body });
    let parsed = {};
    try {
        parsed = JSON.parse(await response.text());
    } catch {
        // An empty answer, or the error page of a module the suite has already let go of.
    }

    return { status: response.status(), body: parsed };
}

async function openPlaceholders() {
    const { body } = await api('GET', `/api/log/${id}`);

    return body.filter((entry) => entry.upload && !entry.img);
}

async function placeholdersWithin(seconds) {
    const until = Date.now() + seconds * 1000;
    for (;;) {
        const open = await openPlaceholders();
        if (open.length > 0 || Date.now() >= until) {
            return open;
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
}

async function moduleStatus() {
    return (await api('GET', `/api/info/${id}`)).body.status;
}

async function waitFinished(seconds) {
    await api('GET', `/api/runner/${id}/wait-state?states=FINISHED,INTERRUPTED&timeoutMs=${seconds * 1000}`);
}

const browser = await chromium.launch({
    args: env.CONFORMANCE_BROWSER_RESOLVER_RULES ? [`--host-resolver-rules=${env.CONFORMANCE_BROWSER_RESOLVER_RULES}`] : [],
});
const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1280, height: 900 } });
const navigations = [];
context.on('request', (sent) => {
    if (sent.isNavigationRequest()) {
        navigations.push({ at: Date.now(), url: sent.url() });
    }
});

// The pages of the OP, answered as the "browser" section of configuration.json answers them.
async function answer(page) {
    const visible = (selector) => page.locator(selector).isVisible().catch(() => false);
    if (await visible('#address')) {
        await page.fill('#address', env.BEFFROI_DEV_USERNAME);
        await submit(page, 'form[data-step="address"] button[type=submit]');

        return 'address';
    }
    if (await visible('#password')) {
        if (await visible('#username')) {
            await page.fill('#username', env.BEFFROI_DEV_USERNAME);
        }
        await page.fill('#password', env.BEFFROI_DEV_USER_PASSWORD);
        await submit(page, 'form[action^="/login"] button[type=submit]');

        return 'sign in';
    }
    if (await visible('button[name=answer][value=allow]')) {
        await submit(page, 'button[name=answer][value=allow]');

        return 'allow';
    }
    if (await visible('button[name=confirm][value=yes]')) {
        await submit(page, 'button[name=confirm][value=yes]');

        return 'sign out';
    }

    return null;
}

async function submit(page, selector) {
    await Promise.all([
        page.waitForEvent('framenavigated', { predicate: (frame) => frame === page.mainFrame(), timeout: 15000 }),
        page.click(selector),
    ]);
    await page.waitForLoadState('networkidle');
}

async function capture(page, placeholder, status) {
    mkdirSync(directory, { recursive: true });
    const name = `${module}${captures.length === 0 ? '' : `-${captures.length + 1}`}.png`;
    const png = await page.screenshot({ path: `${directory}/${name}`, fullPage: true });
    const upload = await api('POST', `/api/log/${id}/images/${placeholder.upload}`, {
        type: 'text/plain',
        body: `data:image/png;base64,${png.toString('base64')}`,
    });
    if (upload.status !== 200) {
        throw new Failed(`the suite refused the capture of the ${pageName} page: HTTP ${upload.status}`);
    }
    captures.push({ file: `${plan}/${name}`, url: page.url(), status, asked: placeholder.msg });
    say(`captured ${plan}/${name}, for "${placeholder.msg}"`);
}

async function staysOn(page, capturedAt) {
    const url = page.url();
    await waitFinished(10);
    await page.waitForTimeout(STILL_SECONDS * 1000);
    const left = navigations.find((navigation) => navigation.at > capturedAt);
    if (left !== undefined || page.url() !== url) {
        throw new Failed(`the browser left the ${pageName} page for ${left?.url ?? page.url()}`);
    }
}

async function visit(url) {
    await api('POST', `/api/runner/browser/${id}/visit?url=${encodeURIComponent(url)}`);
    const page = await context.newPage();
    let status = null;
    page.on('response', (response) => {
        if (response.request().isNavigationRequest() && response.frame() === page.mainFrame()) {
            status = response.status();
        }
    });
    try {
        await page.goto(url, { waitUntil: 'networkidle' });
        say(`open ${new URL(url).pathname}: ${status}`);
        for (let steps = 0; steps < STEPS; steps++) {
            const here = new URL(page.url());
            if (here.origin === suiteOrigin) {
                // What the "Verify complete" task of the scripted browser waits for.
                await page.locator('#submission_complete').waitFor({ state: 'attached', timeout: 10000 }).catch(() => {
                    throw new Failed(`the suite did not complete its page ${here.pathname}`);
                });
                say(`back to the suite on ${here.pathname}`);

                return;
            }
            if (here.origin !== issuer) {
                throw new Failed(`the browser was sent to ${here.href}, which is neither the OP nor the suite`);
            }
            if ((await page.locator(expected.shows).count()) > 0) {
                const open = await placeholdersWithin(PLACEHOLDER_SECONDS);
                if (open.length > 0) {
                    if (status !== expected.status) {
                        throw new Failed(`the ${pageName} page on ${here.pathname} answered ${status} where ${expected.status} is expected`);
                    }
                    const capturedAt = Date.now();
                    await capture(page, open[0], status);
                    if (expected.ends) {
                        await staysOn(page, capturedAt);

                        return;
                    }
                } else if (expected.ends) {
                    throw new Failed(`the ${pageName} page on ${here.pathname} came while the module asked for no capture`);
                }
            }
            const answered = await answer(page);
            if (answered !== null) {
                say(answered);
                continue;
            }
            // The answer of form_post submits itself.
            const left = await page.waitForURL((next) => next.href !== here.href, { timeout: 5000 }).then(
                () => true,
                () => false,
            );
            if (!left) {
                throw new Failed(`nothing to answer on ${here.pathname} (HTTP ${status}), where the module asks for the ${pageName} page`);
            }
            await page.waitForLoadState('networkidle');
        }
        throw new Failed(`still on the OP after ${STEPS} pages, at ${page.url()}`);
    } finally {
        await page.close();
    }
}

async function run() {
    const visited = new Set();
    const deadline = Date.now() + MODULE_SECONDS * 1000;
    let lastVisit = Date.now();
    for (;;) {
        const status = await moduleStatus();
        if (status === 'FINISHED' || status === 'INTERRUPTED') {
            break;
        }
        if (Date.now() >= deadline) {
            throw new Failed(`the module is still ${status} after ${MODULE_SECONDS} seconds`);
        }
        const runner = await api('GET', `/api/runner/${id}`);
        const pending = (runner.body.browser?.urls ?? []).filter((url) => !visited.has(url));
        for (const url of pending) {
            visited.add(url);
            await visit(url);
            lastVisit = Date.now();
        }
        if (pending.length > 0) {
            continue;
        }
        if (Date.now() - lastVisit >= QUIET_SECONDS * 1000) {
            const open = await openPlaceholders();
            throw new Failed(
                open.length > 0
                    ? `the module asks for "${open[0].msg}", and the ${pageName} page never came`
                    : `the module waits, and publishes no URL to visit`,
            );
        }
        await waitFinished(2);
    }
    const left = await openPlaceholders();
    if (left.length > 0) {
        throw new Failed(`the module finished with a placeholder left empty: "${left[0].msg}"`);
    }
    if (captures.length === 0) {
        throw new Failed(`the module finished, and the ${pageName} page never came`);
    }
}

let code = 0;
try {
    await run();
} catch (error) {
    say(`FAILED: ${error.message}`);
    code = error instanceof Failed ? 1 : 2;
} finally {
    mkdirSync(directory, { recursive: true });
    writeFileSync(
        `${directory}/${module}.json`,
        `${JSON.stringify({ module, page: pageName, log: `${env.CONFORMANCE_SUITE}/log-detail.html?log=${id}`, captures, trail }, null, 4)}\n`,
    );
    await context.close();
    await browser.close();
    await suite.dispose();
}
process.exit(code);
