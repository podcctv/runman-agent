// Run via RUNMAN_TEST_BROWSER=1 go test ./web -run TestBrowserLogin -v.
// Playwright must be available to Node; dashboard responses are fixture data.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

(async () => {
    const base = process.argv[2];
    const output = process.env.RUNMAN_UI_OUTPUT;
    if (output) await fs.mkdir(output, { recursive: true });
    const browser = await chromium.launch({ headless: true });
    try {
        const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: 'zh-CN' });
        // Terminal/Tailwind CDNs belong to the existing dashboard, not the login
        // page. Stub them for this authentication-only browser fixture.
        await context.route('https://**/*', route => route.fulfill({ body: '', contentType: 'text/javascript' }));
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.goto(base);
        await page.waitForURL(/\/login\?/);
        await page.getByRole('heading', { name: '登录控制台' }).waitFor();
        assert.equal(await page.locator('#username').evaluate(el => el === document.activeElement), true);
        assert.equal(await page.locator('form').count(), 1);
        assert.equal(await page.locator('script[src]').count(), 0, 'login must work without a CDN');
        if (output) await page.screenshot({ path: path.join(output, 'login-desktop.png'), fullPage: true });

        await page.getByLabel('账号', { exact: true }).fill('admin');
        await page.getByLabel('密码', { exact: true }).fill('wrong-password');
        await page.getByRole('button', { name: '登录', exact: true }).click();
        await page.getByRole('alert').filter({ hasText: '账号或密码不正确' }).waitFor();
        assert.equal(await page.locator('#password').inputValue(), '');
        assert.equal(await page.locator('#password').getAttribute('aria-invalid'), 'true');
        assert.equal(await page.locator('#password').evaluate(el => el === document.activeElement), true);
        if (output) await page.screenshot({ path: path.join(output, 'login-error.png'), fullPage: true });

        await page.getByLabel('密码', { exact: true }).fill('test-password');
        await page.locator('#password-toggle').click();
        assert.equal(await page.locator('#password').getAttribute('type'), 'text');
        assert.equal(await page.locator('#password-toggle').getAttribute('aria-pressed'), 'true');
        await page.locator('#password-toggle').click();
        await page.getByRole('button', { name: 'Switch to English' }).click();
        await page.getByRole('heading', { name: 'Sign in to your console' }).waitFor();
        assert.equal(await page.locator('#password').inputValue(), 'test-password');
        await page.getByRole('button', { name: '切换为中文' }).click();
        await page.getByLabel('密码', { exact: true }).press('Enter');
        await page.waitForURL(base + '/');
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        await page.waitForURL(/reason=logout/);
        assert.equal((await context.cookies()).some(cookie => cookie.name === 'runman_session'), false);
        assert.equal((await context.request.get(base + '/api/config')).status(), 401);

        await page.route('**/api/auth/login', async route => {
            await new Promise(resolve => setTimeout(resolve, 300));
            await route.abort();
        });
        await page.getByLabel('账号', { exact: true }).fill('admin');
        await page.getByLabel('密码', { exact: true }).fill('test-password');
        await page.locator('#submit').click();
        assert.equal(await page.locator('#submit').isDisabled(), true);
        await page.getByRole('alert').filter({ hasText: '无法连接服务器' }).waitFor();
        assert.equal(await page.locator('#submit').isEnabled(), true);
        await page.unroute('**/api/auth/login');

        await page.goto(base + '/login');
        await page.getByLabel('账号', { exact: true }).fill('admin');
        await page.getByLabel('密码', { exact: true }).fill('test-password');
        await page.locator('#submit').click();
        await page.waitForURL(base + '/');
        await context.clearCookies();
        await page.evaluate(() => api('GET', '/api/config').catch(() => {}));
        await page.waitForURL(/reason=expired/);
        await page.getByRole('alert').filter({ hasText: '登录已过期' }).waitFor();

        for (const [name, width, height] of [['mobile', 375, 812], ['small-mobile', 320, 740], ['landscape', 812, 375], ['tablet', 768, 1024]]) {
            await page.setViewportSize({ width, height });
            await page.goto(base + '/login');
            assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, name + ' overflow');
            for (const selector of ['#submit', '#password-toggle', '#language']) {
                assert.ok((await page.locator(selector).boundingBox()).height >= 44, selector + ' touch target');
            }
            if (output) await page.screenshot({ path: path.join(output, `login-${name}.png`), fullPage: true });
        }
        await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' });
        assert.equal(await page.locator('#submit').evaluate(el => getComputedStyle(el).transitionDuration), '0s');
        assert.equal(await page.evaluate(() => localStorage.length), 0, 'no login material in local storage');
        assert.equal(await page.evaluate(() => sessionStorage.length), 0, 'no login material in session storage');
        assert.deepEqual(errors, [], 'unexpected JavaScript errors');
        console.log('Browser checks passed: login, validation, language, keyboard, logout, expiry, network errors, responsive layout and reduced motion.');
        if (output) console.log('Screenshots: ' + output);
        await context.close();
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
