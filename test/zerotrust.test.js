const assert = require("node:assert/strict");
const test = require("node:test");

const { evaluatePolicy } = require("../src/zerotrust/pdp");
const { buildAuditEntry } = require("../src/zerotrust/audit");
const { createDenialMonitor } = require("../src/zerotrust/security-monitor");

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

test("ADMIN has only the explicitly granted actions", () => {
    assert.equal(
        evaluatePolicy(
            { username: "admin", role: "ADMIN" },
            "DELETE",
            "/api/profile"
        ).decision,
        "ALLOW"
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

test("repeated denials create a stage-one rate limit", () => {
    let now = 0;
    const monitor = createDenialMonitor({
        threshold: 3,
        windowMs: 5 * 60 * 1000,
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
        { stage: 1, retryAfterSeconds: 300 }
    );
});

test("three denials after stage one escalate to a one-hour cooldown", () => {
    let now = 0;
    const monitor = createDenialMonitor({ clock: () => now });
    const denial = {
        user: "riddhi", role: "USER", action: "GET",
        resource: "/api/admin", decision: "DENY"
    };

    monitor.recordDecision(denial);
    monitor.recordDecision(denial);
    monitor.recordDecision(denial);
    now += 5 * 60 * 1000;

    assert.equal(monitor.recordDecision(denial), null);
    now += 1_000;
    assert.equal(monitor.recordDecision(denial), null);
    now += 1_000;
    const securityEvent = monitor.recordDecision(denial);
    assert.equal(securityEvent.type, "RATE_LIMIT_ESCALATED");
    assert.equal(securityEvent.deniedAttemptCount, 3);
    assert.deepEqual(
        monitor.getRateLimit({ user: "riddhi", role: "USER", resource: "/api/admin" }),
        { stage: 2, retryAfterSeconds: 3600 }
    );
});

test("an allowed request after stage one resets the user", () => {
    let now = 0;
    const monitor = createDenialMonitor({ clock: () => now });
    const denial = {
        user: "riddhi", role: "USER", action: "GET",
        resource: "/api/admin", decision: "DENY"
    };

    monitor.recordDecision(denial);
    monitor.recordDecision(denial);
    monitor.recordDecision(denial);
    now += 5 * 60 * 1000;
    monitor.recordDecision({ ...denial, decision: "ALLOW" });

    assert.equal(
        monitor.getRateLimit({ user: "riddhi", role: "USER", resource: "/api/admin" }),
        null
    );
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
