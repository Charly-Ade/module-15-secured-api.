#!/usr/bin/env node
/**
 * Pre-deployment security check. Run with:  npm run predeploy
 * Static checks on the repo, then boots the BUILT server (dist/) in production mode on a random
 * port and probes it. Exit code 1 if any check FAILS. SKIP/WARN means "could not verify".
 */
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const results = [];
const record = (area, name, status, detail = "") => results.push({ area, name, status, detail });
const check = (area, name, ok, detail = "") => record(area, name, ok ? "PASS" : "FAIL", detail);
const rand = (n = 48) => crypto.randomBytes(n).toString("base64url");
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");

/* ------------------------------ static checks ------------------------------ */
{
  const gi = fs.existsSync(path.join(root, ".gitignore")) ? read(".gitignore") : "";
  check("secrets", ".env is gitignored", /^\.env\s*$/m.test(gi));

  const git = spawnSync("git", ["ls-files", ".env"], { cwd: root, encoding: "utf8" });
  if (git.status !== 0)
    record(
      "secrets",
      ".env not tracked by git",
      "SKIP",
      "not a git repo here; run inside your portfolio repo",
    );
  else check("secrets", ".env not tracked by git", git.stdout.trim() === "");

  const example = fs.existsSync(path.join(root, ".env.example")) ? read(".env.example") : "";
  const leaked = example
    .split("\n")
    .filter((l) => /(SECRET|PASSWORD)\s*=/.test(l) && !/=\s*$/.test(l));
  check("secrets", ".env.example has no secret values", leaked.length === 0, leaked.join("; "));

  const hits = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ts|js|mjs|json)$/.test(e.name)) {
        const text = fs.readFileSync(p, "utf8");
        if (
          /(secret|password|token|api[_-]?key)\s*[:=]\s*["'][A-Za-z0-9+/_\-.=]{16,}["']/i.test(
            text,
          ) ||
          /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)
        )
          hits.push(path.relative(root, p));
      }
    }
  };
  walk(path.join(root, "src"));
  check("secrets", "no hard-coded secrets in src/", hits.length === 0, hits.join(", "));

  check("deps", "package-lock.json present", fs.existsSync(path.join(root, "package-lock.json")));

  const audit = spawnSync("npm", ["audit", "--audit-level=moderate"], {
    cwd: root,
    encoding: "utf8",
  });
  const out = `${audit.stdout}${audit.stderr}`;
  if (audit.status === 0)
    record(
      "deps",
      "npm audit (moderate+)",
      "PASS",
      (out.match(/found \d+ vulnerabilities/) ?? [""])[0],
    );
  else if (/ENOTFOUND|ECONN|EAI_AGAIN|network|audit endpoint returned an error/i.test(out))
    record("deps", "npm audit (moderate+)", "SKIP", "registry unreachable: re-run with network");
  else
    record(
      "deps",
      "npm audit (moderate+)",
      "FAIL",
      (out.match(/\d+ (?:low|moderate|high|critical)[^\n]*/g) ?? ["see npm audit"]).join("; "),
    );

  const build = spawnSync("npm", ["run", "build"], { cwd: root, encoding: "utf8" });
  check(
    "build",
    "TypeScript build succeeds",
    build.status === 0,
    build.status === 0 ? "" : build.stdout.slice(-300),
  );
}

/* ------------------------------ runtime checks ------------------------------ */
const entry = path.join(root, "dist", "index.js");
const baseEnv = () => ({
  PATH: process.env.PATH,
  NODE_ENV: "production",
  TRUST_PROXY: "1",
  JWT_ACCESS_SECRET: rand(),
  JWT_REFRESH_SECRET: rand(),
  CORS_ORIGINS: "https://app.example.com",
});

const bootExit = (env) =>
  spawnSync(process.execPath, [entry], { env, encoding: "utf8", timeout: 15000 });

if (!fs.existsSync(entry)) {
  record("runtime", "built server found", "FAIL", "dist/index.js missing (build failed?)");
} else {
  const refuses = (label, env, expectText) => {
    const r = bootExit({ PORT: "3999", ...env });
    check("config", label, r.status === 1 && expectText.test(r.stderr), `exit=${r.status}`);
  };
  refuses(
    "refuses to boot with no configuration",
    { PATH: process.env.PATH, NODE_ENV: "production" },
    /JWT_ACCESS_SECRET/,
  );
  refuses("refuses wildcard CORS", { ...baseEnv(), CORS_ORIGINS: "*" }, /CORS_ORIGINS/);
  refuses(
    "refuses identical JWT secrets",
    (() => {
      const e = baseEnv();
      e.JWT_REFRESH_SECRET = e.JWT_ACCESS_SECRET;
      return e;
    })(),
    /JWT_REFRESH_SECRET/,
  );
  refuses(
    "refuses short JWT secret",
    { ...baseEnv(), JWT_ACCESS_SECRET: "short" },
    /JWT_ACCESS_SECRET/,
  );
  refuses(
    "refuses production without TRUST_PROXY (HTTPS enforcement needs it)",
    { ...baseEnv(), TRUST_PROXY: "0" },
    /TRUST_PROXY/,
  );

  const port = 3500 + Math.floor(Math.random() * 400);
  const env = {
    ...baseEnv(),
    PORT: String(port),
    AUTH_RATE_LIMIT_MAX: "8",
    RATE_LIMIT_MAX: "1000",
  };
  const child = spawn(process.execPath, [entry], { env, stdio: ["ignore", "pipe", "pipe"] });
  let serverOutput = "";
  child.stdout.on("data", (d) => (serverOutput += d));
  child.stderr.on("data", (d) => (serverOutput += d));
  const base = `http://127.0.0.1:${port}`;
  const https = { "x-forwarded-proto": "https" }; // what the TLS-terminating proxy would add
  const call = (p, { method = "GET", headers = {}, body, raw, proto = true } = {}) =>
    fetch(base + p, {
      method,
      redirect: "manual",
      headers: {
        ...(proto ? https : {}),
        ...(body && !raw ? { "content-type": "application/json" } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
    });

  try {
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      try {
        up = (await call("/")).status === 200;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    check(
      "runtime",
      "built server boots in production mode",
      up,
      up ? "" : serverOutput.slice(-300),
    );

    if (up) {
      const pw = "predeploy-Password-1";
      const email = `probe${Date.now()}@example.com`;

      const plainGet = await call("/api/accounts", { proto: false });
      check(
        "transport",
        "plain-HTTP GET is redirected to HTTPS (308)",
        plainGet.status === 308 && (plainGet.headers.get("location") ?? "").startsWith("https://"),
      );
      const plainPost = await call("/api/auth/login", {
        method: "POST",
        proto: false,
        body: { email, password: pw },
      });
      check(
        "transport",
        "plain-HTTP login is refused (403), never processed",
        plainPost.status === 403,
      );

      const root_ = await call("/");
      const h = (n) => root_.headers.get(n);
      check(
        "headers",
        "helmet headers present",
        !!h("strict-transport-security") &&
          h("x-content-type-options") === "nosniff" &&
          !!h("x-frame-options") &&
          !!h("content-security-policy"),
      );
      check("headers", "X-Powered-By removed", h("x-powered-by") === null);

      const evil = await call("/", { headers: { origin: "https://evil.example" } });
      const good = await call("/", { headers: { origin: "https://app.example.com" } });
      check(
        "cors",
        "unlisted origin gets no CORS allow header",
        evil.headers.get("access-control-allow-origin") === null,
      );
      check(
        "cors",
        "listed origin echoed exactly, never *",
        good.headers.get("access-control-allow-origin") === "https://app.example.com",
      );

      check(
        "authn",
        "protected route without token -> 401",
        (await call("/api/accounts")).status === 401,
      );
      check(
        "authn",
        "garbage bearer token -> 401",
        (await call("/api/accounts", { headers: { authorization: "Bearer a.b.c" } })).status ===
          401,
      );

      const weakPw = "tiny"; // 4 chars: below the 8-char minimum
      const weak = await call("/api/auth/register", {
        method: "POST",
        body: { name: "Probe User", email: `weak-${email}`, password: weakPw },
      });
      const weakBody = await weak.text();
      check(
        "input",
        "too-short password rejected with exactly 400",
        weak.status === 400,
        `status ${weak.status}`,
      );
      check("input", "validation error never echoes the password", !weakBody.includes(weakPw));

      const reg = await call("/api/auth/register", {
        method: "POST",
        body: { name: "Probe User", email, password: pw },
      });
      const regText = await reg.text();
      check(
        "authn",
        "register works; response has no password/hash",
        reg.status === 201 && !/password|\$2b\$|passwordHash/i.test(regText),
        `status ${reg.status}`,
      );
      const login = await call("/api/auth/login", {
        method: "POST",
        body: { email, password: pw },
      });
      const tokens = await login.json();
      check(
        "authn",
        "login returns separate access + refresh tokens",
        login.status === 200 &&
          !!tokens.accessToken &&
          !!tokens.refreshToken &&
          tokens.accessToken !== tokens.refreshToken,
      );

      const admin = await call("/api/admin/users", {
        headers: { authorization: `Bearer ${tokens.accessToken}` },
      });
      check("authz", "admin route: logged-in non-admin -> 403 (not 401)", admin.status === 403);
      check(
        "authz",
        "admin route: anonymous -> 401",
        (await call("/api/admin/users")).status === 401,
      );

      const nf = await call("/api/does-not-exist");
      const nfText = await nf.text();
      check(
        "errors",
        "unknown route -> JSON 404, no stack trace",
        nf.status === 404 && !/at .*\(|node_modules|\.ts:/.test(nfText),
      );
      check(
        "errors",
        "malformed JSON -> 400",
        (
          await call("/api/auth/login", {
            method: "POST",
            raw: true,
            body: "{oops",
            headers: { "content-type": "application/json" },
          })
        ).status === 400,
      );
      check(
        "errors",
        "oversized body -> 413",
        (
          await call("/api/auth/login", {
            method: "POST",
            body: { email, password: "x".repeat(20000) },
          })
        ).status === 413,
      );

      let limitedAt = 0;
      for (let i = 1; i <= 15 && !limitedAt; i++) {
        const r = await call("/api/auth/login", {
          method: "POST",
          body: { email, password: "definitely-wrong-1" },
        });
        if (r.status === 429) limitedAt = i;
      }
      check(
        "ratelimit",
        "login brute force is rate limited (429)",
        limitedAt > 0,
        limitedAt ? `blocked after ${limitedAt} more attempts` : "never blocked in 15 tries",
      );

      await new Promise((r) => setTimeout(r, 300));
      const leakedInLogs = [
        pw,
        tokens.accessToken,
        tokens.refreshToken,
        email,
        env.JWT_ACCESS_SECRET,
        env.JWT_REFRESH_SECRET,
        "$2b$",
      ].filter((s) => serverOutput.includes(s));
      check(
        "logging",
        "server logs contain no passwords, tokens, secrets or raw emails",
        leakedInLogs.length === 0,
        leakedInLogs.length ? "LEAK FOUND" : "",
      );
      check(
        "logging",
        "security events are being logged",
        /"type":"security"/.test(serverOutput) &&
          /login_failed/.test(serverOutput) &&
          /rate_limited/.test(serverOutput),
      );
    }
  } finally {
    child.kill();
  }
}

/* ------------------------------ report ------------------------------ */
const icon = { PASS: "PASS", FAIL: "FAIL", SKIP: "SKIP" };
const width = Math.max(...results.map((r) => r.name.length));
let lastArea = "";
for (const r of results) {
  if (r.area !== lastArea) {
    console.log(`\n[${r.area}]`);
    lastArea = r.area;
  }
  console.log(`  ${icon[r.status]}  ${r.name.padEnd(width)}${r.detail ? "  - " + r.detail : ""}`);
}
const count = (s) => results.filter((r) => r.status === s).length;
console.log(
  `\n${count("PASS")} passed, ${count("FAIL")} failed, ${count("SKIP")} skipped (of ${results.length})`,
);
console.log(
  "Reminder: this proves the app's behaviour. TLS certificates, secrets storage, backups and monitoring are deployment-time items; see NOTES.md.",
);
process.exit(count("FAIL") ? 1 : 0);
