/**
 * Checks that the served page offers a step only when that step can succeed.
 *
 * The page's "Issue today's" button is drawn from `ops::Stage`, which arrives
 * on `/api/status`. Rust tests can prove the stage reaches the page and that
 * the page has words for every stage, but the gate itself is a line of
 * JavaScript, and no `cargo test` executes it. This does — against a real
 * server, with the vault actually in the stage being claimed.
 *
 * Exits non-zero on the first mismatch, so a caller can drive a vault through
 * the whole on-ramp and fail at whichever rung broke.
 *
 *   node tools/ui-preview/onramp.mjs <url-with-token> <expected-stage>
 */
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_PATH ?? "playwright");

const [url, expected] = process.argv.slice(2);
if (!url || !expected) {
  console.error("usage: onramp.mjs <url-with-token> <expected-stage>");
  process.exit(2);
}

/* The one rule. A button that cannot succeed teaches the user that the product
   is broken; a missing button teaches them it is finished. Both are wrong in a
   way only a rendered page shows. */
const SHOULD_OFFER_ISSUE = new Set(["no_open_quests"]);

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
});
const ctx = await browser.newContext({
  viewport: { width: 428, height: 926 },
  isMobile: true,
  hasTouch: true,
});
const page = await ctx.newPage();

const problems = [];
page.on("pageerror", (e) => problems.push("pageerror: " + e.message));
page.on("console", (m) => {
  if (m.type() === "error") problems.push("console: " + m.text());
});

await page.goto(url, { waitUntil: "networkidle" });
await page.waitForTimeout(800);

/* Read the stage from the server rather than from the page's own rendering:
   asking the page what stage it thinks it is in would let a page that ignores
   the field agree with itself. The token comes from the argument rather than
   from `location.hash`, because the page moves it to localStorage and clears
   the fragment on first load. */
const token = (url.match(/[#&]t=([a-f0-9]{64})/i) ?? [])[1];
if (!token) {
  console.error("  \u2717 no token in the URL; pass the link `ghostr serve` printed");
  await browser.close();
  process.exit(2);
}
const stage = await page.evaluate(async (t) => {
  const r = await fetch("/api/status", { headers: { Authorization: "Bearer " + t } });
  return (await r.json()).stage;
}, token);

if (stage !== expected) {
  problems.push(`vault is in stage \`${stage}\`, expected \`${expected}\``);
}

await page.getByText("Quests", { exact: true }).last().tap();
await page.waitForTimeout(700);

const button = await page.locator("#issue").count();
const shouldHave = SHOULD_OFFER_ISSUE.has(stage);
if (shouldHave && button === 0) {
  problems.push(`stage \`${stage}\` can issue, but the page offers no button`);
}
if (!shouldHave && button > 0) {
  problems.push(
    `stage \`${stage}\` cannot issue, but the page offers a button that will fail`,
  );
}

/* A gated button is only half the promise: the other half is that the page
   said *something* about what to do instead. An empty card is a dead end even
   when no button lies about it. */
const text = await page.evaluate(() => document.body.innerText);
if (!shouldHave && text.trim().split("\n").length < 3) {
  problems.push(`stage \`${stage}\` shows no guidance: ${JSON.stringify(text)}`);
}

await browser.close();

if (problems.length) {
  for (const p of problems) console.error("  ✗ " + p);
  process.exit(1);
}
console.log(`  ✓ ${stage}: ${shouldHave ? "button offered" : "guidance, no button"}`);
