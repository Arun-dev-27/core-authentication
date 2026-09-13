import { mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { Page, chromium } from 'playwright';

/**
 * Real-browser (Chromium) end-to-end test of the embedded login federation.
 * Verifies what HTTP tests cannot: iframe rendering, CSP frame-ancestors enforcement, postMessage
 * delivery to the exact parent origin, cookies in a real browser, SSO, portal launch and logout.
 *
 * Prerequisites: all services running (Identity 3001, Authorization 3002, RMS 4001, AMS 4002, VMS 4003)
 *   npx playwright install chromium
 *   BROWSER_ITS_ID=30337752 BROWSER_PASSWORD=... node -r ts-node/register/transpile-only test/browser/federation.browser-e2e.ts
 */

const IDENTITY = 'http://localhost:3001';
const ITS_ID = process.env.BROWSER_ITS_ID ?? '30337752';
const PASSWORD = process.env.BROWSER_PASSWORD;
const SHOTS = process.env.BROWSER_SCREENSHOTS ?? join(process.cwd(), '.browser-e2e');
const results: { check: string; ok: boolean; detail?: string }[] = [];

function record(check: string, ok: boolean, detail?: string) {
  results.push({ check, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${check}${detail ? `  (${detail})` : ''}`);
}

async function signedIn(page: Page, appName: string) {
  try {
    await page.getByText('Federation sid').waitFor({ timeout: 20_000 });
    return true;
  } catch {
    await page.screenshot({ path: join(SHOTS, `fail-${appName}.png`), fullPage: true });
    return false;
  }
}

async function main() {
  if (!PASSWORD) throw new Error('BROWSER_PASSWORD is required');
  mkdirSync(SHOTS, { recursive: true });
  const browser = await chromium.launch({ headless: process.env.HEADED !== '1' });
  const context = await browser.newContext();
  const page = await context.newPage();
  const cspViolations: string[] = [];
  page.on('console', (msg) => {
    if (/Content Security Policy|frame-ancestors/i.test(msg.text())) cspViolations.push(msg.text());
  });

  // 1. RMS: password sign-in inside the iframe
  await page.goto('http://localhost:4001/');
  const frame = page.frameLocator('iframe.miqaat-login');
  await frame.locator('#identifier').waitFor({ timeout: 20_000 });
  await page.screenshot({ path: join(SHOTS, '01-rms-embedded-login.png'), fullPage: true });
  record('RMS renders Core login inside iframe', true);

  const parentCanReadFrame = await page.evaluate(() => {
    try {
      return Boolean((document.querySelector('iframe.miqaat-login') as HTMLIFrameElement).contentDocument?.body);
    } catch {
      return false;
    }
  });
  record('RMS page cannot read the Core iframe DOM (credentials isolated)', !parentCanReadFrame);

  await frame.locator('#identifier').fill(ITS_ID);
  await frame.locator('#password').fill(PASSWORD);
  await frame.getByRole('button', { name: 'Sign in' }).click();
  record('RMS: postMessage handoff -> backend JWKS verification -> rms_session', await signedIn(page, 'rms'));
  await page.screenshot({ path: join(SHOTS, '02-rms-signed-in.png'), fullPage: true });

  await page.getByRole('button', { name: 'delete' }).click();
  await page.getByText('"allowed": true').waitFor({ timeout: 10_000 }).then(
    () => record('RMS: RMS Registration Admin allowed RMS_REGISTRATION_DELETE (server-side check)', true),
    () => record('RMS: RMS Registration Admin allowed RMS_REGISTRATION_DELETE (server-side check)', false),
  );

  const cookies = await context.cookies(IDENTITY);
  const fed = cookies.find((c) => c.name === 'federation_session');
  record('federation_session cookie is HttpOnly, Secure, SameSite=None', Boolean(fed && fed.httpOnly && fed.secure && fed.sameSite === 'None'));
  record('federation_session is not readable from JavaScript', !(await page.evaluate(() => document.cookie.includes('federation_session'))));

  // 2. AMS and VMS: SSO (Continue as ...)
  for (const [name, url] of [['AMS', 'http://localhost:4002/'], ['VMS', 'http://localhost:4003/']] as const) {
    await page.goto(url);
    const f = page.frameLocator('iframe.miqaat-login');
    const cont = f.getByRole('button', { name: /Continue to/ });
    await cont.waitFor({ timeout: 20_000 });
    await page.screenshot({ path: join(SHOTS, `03-${name.toLowerCase()}-sso-continue.png`), fullPage: true });
    await cont.click();
    record(`${name}: SSO without password -> own local session`, await signedIn(page, name.toLowerCase()));
  }
  await page.getByRole('button', { name: 'create' }).click();
  await page.getByText('"allowed": false').waitFor({ timeout: 10_000 }).then(
    () => record('VMS: VMS Viewer denied VMS_EVENTS_CREATE (different role per app)', true),
    () => record('VMS: VMS Viewer denied VMS_EVENTS_CREATE (different role per app)', false),
  );

  // 3. Core Portal: Select Workspace (role x scope) -> Switch Workspace -> application selection
  await page.goto(`${IDENTITY}/portal`);
  const workspaceGroup = page.getByRole('radiogroup', { name: 'Workspaces' });
  await workspaceGroup.waitFor({ timeout: 20_000 });
  const workspaceNames = await page.locator('.app-name').allTextContents();
  record('Portal shows Select Workspace with every role x scope', ['Platform Administrator', 'RMS Registration Admin', 'VMS Viewer'].every((n) => workspaceNames.includes(n)), workspaceNames.join(', '));
  await page.screenshot({ path: join(SHOTS, '04a-portal-select-workspace.png'), fullPage: true });
  await page.locator('label.app-option', { hasText: 'Platform Administrator' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('radiogroup', { name: 'Applications' }).waitFor({ timeout: 20_000 });
  const coreBar = (await page.locator('#active-workspace').textContent()) ?? '';
  record('POST /portal/select-scope activates the CORE workspace', coreBar.includes('Platform Administrator') && coreBar.includes('Core'), coreBar.trim());
  await page.getByRole('button', { name: 'Switch workspace' }).click();
  await workspaceGroup.waitFor({ timeout: 20_000 });
  await page.locator('label.app-option', { hasText: 'RMS Registration Admin' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('radiogroup', { name: 'Applications' }).waitFor({ timeout: 20_000 });
  const buBar = (await page.locator('#active-workspace').textContent()) ?? '';
  record('Switch Workspace without logging out (RMS Registration Admin @ RMS)', buBar.includes('RMS Registration Admin') && buBar.includes('Business unit'), buBar.trim());
  const appNames = await page.locator('.app-name').allTextContents();
  record('Portal lists entitled applications', ['RMS Web', 'AMS Web', 'VMS Web'].every((n) => appNames.includes(n)), appNames.join(', '));
  await page.screenshot({ path: join(SHOTS, '04-portal-application-selection.png'), fullPage: true });
  await page.locator('label.app-option', { hasText: 'RMS Web' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForURL(/localhost:4001/, { timeout: 20_000 });
  record('Portal Continue launches RMS via initiate_login_uri', await signedIn(page, 'portal-rms'));

  // 4. Hostile origin cannot frame the login page (CSP frame-ancestors)
  const evil = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<iframe id="x" src="${IDENTITY}/embed/login?client_id=rms-web-dev&transaction_id=txn-browser-evil-${Date.now()}&state=browser-evil-state&origin=http://localhost:4001"></iframe>`);
  });
  await new Promise<void>((r) => evil.listen(4999, '127.0.0.1', r));
  cspViolations.length = 0;
  const evilPage = await context.newPage();
  evilPage.on('console', (msg) => cspViolations.push(msg.text()));
  await evilPage.goto('http://127.0.0.1:4999/');
  await evilPage.waitForTimeout(3000);
  const loginFrame = evilPage.frames().find((fr) => fr.url().includes('/embed/login'));
  const rendered = loginFrame ? await loginFrame.locator('#identifier').count().catch(() => 0) : 0;
  record('Unregistered origin cannot embed login (frame-ancestors blocks)', rendered === 0, cspViolations.find((m) => /frame-ancestors/i.test(m))?.slice(0, 90) ?? 'frame blocked');
  await evilPage.close();
  evil.close();

  // 5. Federation logout from RMS -> back-channel ends AMS and VMS sessions
  await page.goto('http://localhost:4001/');
  await signedIn(page, 'rms-before-logout');
  await page.getByRole('button', { name: 'Sign out everywhere' }).click();
  await page.waitForURL(/logged_out=1/, { timeout: 20_000 });
  record('Federation logout returned to RMS post-logout URI', true);
  await page.waitForTimeout(2000);
  for (const [name, url] of [['AMS', 'http://localhost:4002/'], ['VMS', 'http://localhost:4003/']] as const) {
    await page.goto(url);
    const f = page.frameLocator('iframe.miqaat-login');
    await f.locator('#identifier').waitFor({ timeout: 20_000 }).then(
      () => record(`${name}: signed out by back-channel logout (password required again)`, true),
      () => record(`${name}: signed out by back-channel logout (password required again)`, false),
    );
  }
  await page.screenshot({ path: join(SHOTS, '05-after-federation-logout.png'), fullPage: true });

  await browser.close();
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} browser checks passed; screenshots in ${SHOTS}`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((error: unknown) => {
  console.error('browser e2e error:', error instanceof Error ? error.message : error);
  process.exit(1);
});
