const assert = require("node:assert/strict");
const express = require("express");
const http = require("node:http");
const test = require("node:test");
const { performance } = require("node:perf_hooks");
const jwt = require("jsonwebtoken");

const { evaluatePolicy } = require("../src/zerotrust/pdp");
const { buildAuditEntry } = require("../src/zerotrust/audit");
const { createDenialMonitor } = require("../src/zerotrust/security-monitor");
const authRoutes = require("../src/routes/auth");
const protectedRoutes = require("../src/routes/protected");

test("login timings are similar for existing and nonexistent users", async () => {
    const app = express();
    app.use(express.json());
    app.use("/auth", authRoutes);

    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));

    try {
        const address = server.address();
        const timings = { existing: [], nonexistent: [] };
        const attempts = [
            { key: "existing", username: "Riddhi" },
            { key: "nonexistent", username: "timing-test-missing-user" }
        ];

        for (let index = 0; index < 5; index += 1) {
            for (const attempt of attempts) {
                const startedAt = performance.now();
                const response = await fetch(`http://127.0.0.1:${address.port}/auth/login`, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({ username: attempt.username, password: "wrong-password" })
                });
                timings[attempt.key].push(performance.now() - startedAt);
                assert.equal(response.status, 401);
            }
        }

        const median = values => {
            const sorted = [...values].sort((left, right) => left - right);
            return sorted[Math.floor(sorted.length / 2)];
        };
        const existingMedian = median(timings.existing);
        const nonexistentMedian = median(timings.nonexistent);
        const timingRatio = existingMedian / nonexistentMedian;

        console.log("Login response timings (ms):", JSON.stringify(timings));
        console.log("Login median timing ratio:", timingRatio.toFixed(2));
        assert.ok(
            timingRatio >= 0.33 && timingRatio <= 3,
            `Existing and nonexistent user timing medians differ too much: ${timingRatio.toFixed(2)}x`
        );
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => error ? reject(error) : resolve());
            server.closeAllConnections();
        });
    }
});

test("malformed JSON login requests return a bad request response", async () => {
    const app = express();
    app.use(express.json());
    app.use("/auth", authRoutes);
    app.use((err, req, res, next) => {
        console.error("[Server Error]", err);

        if (
            err instanceof SyntaxError &&
            err.status === 400 &&
            err.type === "entity.parse.failed"
        ) {
            return res.status(400).json({ error: "Bad request" });
        }

        return res.status(500).json({ error: "Internal server error" });
    });

    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));

    try {
        const address = server.address();
        const response = await fetch(`http://127.0.0.1:${address.port}/auth/login`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: "{ malformed json"
        });
        const body = await response.text();
        const contentType = response.headers.get("content-type");

        console.log("Malformed JSON login response:", JSON.stringify({
            status: response.status,
            contentType,
            body
        }));
        assert.equal(response.status, 400);
        assert.match(contentType, /^application\/json\b/);
        assert.deepEqual(JSON.parse(body), { error: "Bad request" });
        assert.doesNotMatch(body, /SyntaxError|node_modules|at JSON\.parse/);
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => error ? reject(error) : resolve());
            server.closeAllConnections();
        });
    }
});

test("protected routes verify the caller's bearer token", async () => {
    const secret = "pep-test-secret";
    const previousSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = secret;

    const token = jwt.sign(
        { username: "riddhi", role: "USER" },
        secret,
        { algorithm: "HS256" }
    );
    const app = express();
    app.use("/api", protectedRoutes);

    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));

    try {
        const address = server.address();
        const response = await fetch(`http://127.0.0.1:${address.port}/api/profile`, {
            headers: { authorization: `Bearer ${token}` }
        });

        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.user.username, "riddhi");
        assert.equal(body.user.role, "USER");
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => error ? reject(error) : resolve());
            server.closeAllConnections();
        });

        if (previousSecret === undefined) {
            delete process.env.JWT_SECRET;
        } else {
            process.env.JWT_SECRET = previousSecret;
        }
    }
});

test("USER may read and update their profile", () => {
    for (const action of ["GET", "POST"]) {
        const decision = evaluatePolicy(
            { username: "riddhi", role: "USER" },
            action,
            "/api/profile"
        );

        assert.equal(decision.decision, "ALLOW");
        assert.equal(decision.user, "riddhi");
    }
});

test("USER is denied an unapproved profile action", () => {
    const decision = evaluatePolicy(
        { username: "riddhi", role: "USER" },
        "DELETE",
        "/api/profile"
    );

    assert.equal(decision.decision, "DENY");
});

test("ADMIN is denied actions without an explicit policy grant", () => {
    assert.equal(
        evaluatePolicy(
            { username: "admin", role: "ADMIN" },
            "DELETE",
            "/api/profile"
        ).decision,
        "DENY"
    );

    assert.equal(
        evaluatePolicy(
            { username: "admin", role: "ADMIN" },
            "POST",
            "/api/admin"
        ).decision,
        "DENY"
    );
});

test("unknown roles are denied by default", () => {
    const decision = evaluatePolicy(
        { username: "visitor", role: "VISITOR" },
        "GET",
        "/api/profile"
    );

    assert.equal(decision.decision, "DENY");
    assert.equal(decision.reason, "Unknown user role");
});

test("repeated denials create a rate limit", () => {
    let now = 0;
    const monitor = createDenialMonitor({
        threshold: 3,
        windowMs: 5 * 60 * 1000,
        cooldownMs: 15 * 60 * 1000,
        clock: () => now
    });
    const denial = {
        user: "riddhi",
        role: "USER",
        action: "DELETE",
        resource: "/api/admin",
        decision: "DENY"
    };

    assert.equal(monitor.recordDecision(denial), null);
    now += 1_000;
    assert.equal(monitor.recordDecision(denial), null);
    now += 1_000;

    const securityEvent = monitor.recordDecision(denial);
    assert.equal(securityEvent.type, "REPEATED_DENIAL");
    assert.equal(securityEvent.deniedAttemptCount, 3);
    assert.equal(securityEvent.username, "riddhi");

    assert.deepEqual(
        monitor.getRateLimit({
            user: "riddhi",
            role: "USER",
            resource: "/api/admin"
        }),
        { retryAfterSeconds: 900 }
    );
});

test("a later, independent round of denials gets the same treatment as the first", () => {
    // Regression test: an earlier version of this monitor permanently
    // flagged a subject after its first rate limit, so any later
    // unrelated round of denials jumped straight to a harsher cooldown
    // even long after the first one had fully expired. There should be
    // no memory of a subject once its cooldown and denial window have
    // both elapsed.
    let now = 0;
    const monitor = createDenialMonitor({
        threshold: 3,
        windowMs: 5 * 60 * 1000,
        cooldownMs: 15 * 60 * 1000,
        clock: () => now
    });
    const denial = {
        user: "riddhi", role: "USER", action: "GET",
        resource: "/api/admin", decision: "DENY"
    };

    monitor.recordDecision(denial);
    monitor.recordDecision(denial);
    monitor.recordDecision(denial);

    // Well past both the cooldown and the denial window.
    now += 20 * 60 * 1000;
    monitor.cleanupExpiredEntries();
    assert.equal(
        monitor.getRateLimit({ user: "riddhi", role: "USER", resource: "/api/admin" }),
        null
    );

    assert.equal(monitor.recordDecision(denial), null);
    now += 1_000;
    assert.equal(monitor.recordDecision(denial), null);
    now += 1_000;
    const securityEvent = monitor.recordDecision(denial);

    assert.equal(securityEvent.type, "REPEATED_DENIAL");
    assert.deepEqual(
        monitor.getRateLimit({ user: "riddhi", role: "USER", resource: "/api/admin" }),
        { retryAfterSeconds: 900 }
    );
});

test("an allowed request resets a subject's denial history", () => {
    let now = 0;
    const monitor = createDenialMonitor({
        threshold: 3,
        windowMs: 5 * 60 * 1000,
        cooldownMs: 15 * 60 * 1000,
        clock: () => now
    });
    const denial = {
        user: "riddhi", role: "USER", action: "GET",
        resource: "/api/admin", decision: "DENY"
    };

    monitor.recordDecision(denial);
    monitor.recordDecision(denial);
    now += 1_000;
    monitor.recordDecision({ ...denial, decision: "ALLOW" });

    // The two prior denials should no longer count toward the threshold.
    assert.equal(monitor.recordDecision(denial), null);
    assert.equal(
        monitor.getRateLimit({ user: "riddhi", role: "USER", resource: "/api/admin" }),
        null
    );
});

test("denial-tracking state does not persist once it has fully expired", () => {
    // Guards against the unbounded-memory issue: a key that is denied
    // once and never revisited should leave no trace after its window
    // has elapsed and cleanup has run.
    let now = 0;
    const monitor = createDenialMonitor({
        threshold: 3,
        windowMs: 5 * 60 * 1000,
        cooldownMs: 15 * 60 * 1000,
        clock: () => now
    });

    for (let i = 0; i < 50; i += 1) {
        monitor.recordDecision({
            user: "riddhi",
            role: "USER",
            action: "GET",
            resource: `/api/scan-${i}`,
            decision: "DENY"
        });
    }

    now += 10 * 60 * 1000;
    monitor.cleanupExpiredEntries();

    for (let i = 0; i < 50; i += 1) {
        assert.equal(
            monitor.getRateLimit({
                user: "riddhi",
                role: "USER",
                resource: `/api/scan-${i}`
            }),
            null
        );
    }
});

test("allowed decisions do not create a security event", () => {
    const monitor = createDenialMonitor();
    const securityEvent = monitor.recordDecision({
        user: "riddhi",
        role: "USER",
        action: "GET",
        resource: "/api/profile",
        decision: "ALLOW"
    });

    assert.equal(securityEvent, null);
});

test("audit entries retain the username from a PDP decision", () => {
    const entry = buildAuditEntry({
        user: "riddhi",
        role: "USER",
        action: "GET",
        resource: "/api/profile",
        decision: "ALLOW",
        reason: "USER is permitted to perform GET on /api/profile"
    });

    assert.equal(entry.username, "riddhi");
    assert.equal(entry.decision, "ALLOW");
    assert.ok(entry.timestamp);
});
