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
    stageOneCooldownMs = 5 * 60 * 1000,
    stageTwoCooldownMs = 60 * 60 * 1000,
    clock = () => Date.now()
} = {}) {
    const deniedAttempts = new Map();
    const stageOneAttempts = new Map();
    const stageOneTriggered = new Set();
    const cooldowns = new Map();

    function buildKey({ user, role, resource }) {
        return `${user}|${role}|${resource}`;
    }

    function cleanupExpiredEntries() {
        const now = clock();

        // Remove denial-tracking entries whose
        // entire observation window has expired.
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

        // Remove expired stage-one tracking entries.
        for (const [key, timestamps] of stageOneAttempts.entries()) {
            const activeAttempts = timestamps.filter(
                timestamp => now - timestamp <= windowMs
            );

            if (activeAttempts.length === 0) {
                stageOneAttempts.delete(key);
            } else {
                stageOneAttempts.set(key, activeAttempts);
            }
        }

        // Remove expired cooldown entries.
        for (const [key, cooldown] of cooldowns.entries()) {
            if (now >= cooldown.expiresAt) {
                cooldowns.delete(key);
            }
        }
    }

    function getRateLimit(subject) {
        const key = buildKey(subject);
        const cooldown = cooldowns.get(key);
        const now = clock();

        if (!cooldown) {
            return null;
        }

        if (now < cooldown.expiresAt) {
            return {
                stage: cooldown.stage,
                retryAfterSeconds: Math.ceil(
                    (cooldown.expiresAt - now) / 1000
                )
            };
        }

        // Cooldown has expired.
        cooldowns.delete(key);

        return null;
    }

    function recordDecision(decision) {
        const key = buildKey(decision);
        const now = clock();

        // Remove stale state before processing
        // the new authorization decision.
        cleanupExpiredEntries();

        /*
         * Existing cooldown/escalation logic
         * remains below.
         */

        if (decision.decision !== "DENY") {
            deniedAttempts.delete(key);
            stageOneAttempts.delete(key);
            stageOneTriggered.delete(key);
            cooldowns.delete(key);
            return null;
        }

        const attemptsByStage = stageOneTriggered.has(key)
            ? stageOneAttempts
            : deniedAttempts;
        const attempts = (attemptsByStage.get(key) || [])
            .filter(
                timestamp => now - timestamp <= windowMs
            );

        attempts.push(now);
        attemptsByStage.set(key, attempts);

        if (attempts.length < threshold) {
            return null;
        }

        const isEscalation = stageOneTriggered.has(key);
        const cooldownDurationMs = isEscalation
            ? stageTwoCooldownMs
            : stageOneCooldownMs;
        const expiresAt = now + cooldownDurationMs;

        cooldowns.set(key, {
            stage: isEscalation ? 2 : 1,
            expiresAt
        });

        if (isEscalation) {
            stageOneAttempts.delete(key);
        } else {
            stageOneTriggered.add(key);
            deniedAttempts.delete(key);
        }

        return {
            timestamp: new Date(now).toISOString(),
            type: isEscalation ? "RATE_LIMIT_ESCALATED" : "REPEATED_DENIAL",
            username: decision.user,
            role: decision.role,
            action: decision.action,
            resource: decision.resource,
            deniedAttemptCount: attempts.length,
            windowSeconds: windowMs / 1000,
            cooldownSeconds: cooldownDurationMs / 1000,
            rateLimitExpiresAt: new Date(expiresAt).toISOString(),
            recommendation: isEscalation
                ? "Review this account's repeated authorization denials."
                : "Review this account's recent authorization activity."
        };
    }

    return {
        recordDecision,
        getRateLimit,
        cleanupExpiredEntries
    };
}

const denialMonitor = createDenialMonitor();

/*
 * Periodically clean stale monitoring state.
 *
 * The interval is intentionally longer than the normal
 * request-processing path so cleanup does not happen
 * on every request.
 */
const cleanupInterval = setInterval(
    () => {
        denialMonitor.cleanupExpiredEntries();
    },
    60 * 1000
);

// Do not keep Node.js alive only because of this timer.
if (cleanupInterval.unref) {
    cleanupInterval.unref();
}

function monitorAuthorizationDecision(decision) {
    const securityEvent =
        denialMonitor.recordDecision(decision);

    if (!securityEvent) {
        return null;
    }

    if (!fs.existsSync(logDirectory)) {
        fs.mkdirSync(logDirectory, {
            recursive: true
        });
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