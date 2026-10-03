const fs = require("fs");
const path = require("path");

const logDirectory = path.join(__dirname, "../../logs");
const securityEventFile = path.join(
    logDirectory,
    "security-events.log"
);

function createDenialMonitor({
    threshold = 3,
    windowMs = 5 * 60 * 1000,
    cooldownMs = 15 * 60 * 1000,
    clock = () => Date.now()
} = {}) {
    // Two maps total: timestamps of recent denials per subject,
    // and an active cooldown expiry per subject. No escalation
    // state to track separately, so there is nothing that can
    // outlive its own timestamps and no parallel structure that
    // can drift out of sync with the others.
    const deniedAttempts = new Map();
    const cooldowns = new Map();

    function buildKey({ user, role, resource }) {
        return `${user}|${role}|${resource}`;
    }

    function cleanupExpiredEntries() {
        const now = clock();

        for (const [key, timestamps] of deniedAttempts.entries()) {
            const activeAttempts = timestamps.filter(
                timestamp => now - timestamp <= windowMs
            );

            if (activeAttempts.length === 0) {
                deniedAttempts.delete(key);
            } else {
                deniedAttempts.set(key, activeAttempts);
            }
        }

        for (const [key, expiresAt] of cooldowns.entries()) {
            if (now >= expiresAt) {
                cooldowns.delete(key);
            }
        }
    }

    function getRateLimit(subject) {
        const key = buildKey(subject);
        const expiresAt = cooldowns.get(key);
        const now = clock();

        if (!expiresAt) {
            return null;
        }

        if (now < expiresAt) {
            return {
                retryAfterSeconds: Math.ceil((expiresAt - now) / 1000)
            };
        }

        cooldowns.delete(key);
        return null;
    }

    function recordDecision(decision) {
        const key = buildKey(decision);
        const now = clock();

        // Remove stale state before processing the new decision,
        // and again on a timer below so idle keys don't linger
        // in memory between requests.
        cleanupExpiredEntries();

        if (decision.decision !== "DENY") {
            deniedAttempts.delete(key);
            cooldowns.delete(key);
            return null;
        }

        const attempts = (deniedAttempts.get(key) || [])
            .filter(timestamp => now - timestamp <= windowMs);

        attempts.push(now);
        deniedAttempts.set(key, attempts);

        if (attempts.length < threshold) {
            return null;
        }

        const expiresAt = now + cooldownMs;
        cooldowns.set(key, expiresAt);
        deniedAttempts.delete(key);

        return {
            timestamp: new Date(now).toISOString(),
            type: "REPEATED_DENIAL",
            username: decision.user,
            role: decision.role,
            action: decision.action,
            resource: decision.resource,
            deniedAttemptCount: attempts.length,
            windowSeconds: windowMs / 1000,
            cooldownSeconds: cooldownMs / 1000,
            rateLimitExpiresAt: new Date(expiresAt).toISOString(),
            recommendation: "Review this account's recent authorization activity."
        };
    }

    return {
        recordDecision,
        getRateLimit,
        cleanupExpiredEntries
    };
}

const denialMonitor = createDenialMonitor();

// Periodically clean stale monitoring state so memory use stays
// bounded by (attack rate x window), not by total traffic ever seen.
const cleanupInterval = setInterval(
    () => {
        denialMonitor.cleanupExpiredEntries();
    },
    60 * 1000
);

if (cleanupInterval.unref) {
    cleanupInterval.unref();
}

function monitorAuthorizationDecision(decision) {
    const securityEvent = denialMonitor.recordDecision(decision);

    if (!securityEvent) {
        return null;
    }

    if (!fs.existsSync(logDirectory)) {
        fs.mkdirSync(logDirectory, { recursive: true });
    }

    fs.appendFileSync(
        securityEventFile,
        JSON.stringify(securityEvent) + "\n"
    );

    return securityEvent;
}

function getRateLimit(subject) {
    return denialMonitor.getRateLimit(subject);
}

module.exports = {
    createDenialMonitor,
    monitorAuthorizationDecision,
    getRateLimit
};
