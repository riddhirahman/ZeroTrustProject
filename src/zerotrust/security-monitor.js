const fs = require("fs");
const path = require("path");

const logDirectory = path.join(__dirname, "../../logs");
const securityEventFile = path.join(logDirectory, "security-events.log");

function createDenialMonitor({
    threshold = 3,
    windowMs = 5 * 60 * 1000,
    stageOneCooldownMs = 5 * 60 * 1000,
    stageTwoCooldownMs = 60 * 60 * 1000,
    clock = () => Date.now()
} = {}) {
    const deniedAttempts = new Map();
    const stageOneAttempts = new Map();
    const cooldowns = new Map();

    function buildKey({ user, role, resource }) {
        return `${user}|${role}|${resource}`;
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
                retryAfterSeconds: Math.ceil((cooldown.expiresAt - now) / 1000)
            };
        }

        // Stage one expiry provides a grace request for normal PDP evaluation.
        if (cooldown.stage === 1) {
            return null;
        }

        cooldowns.delete(key);
        return null;
    }

    function recordDecision(decision) {
        const key = buildKey(decision);
        const now = clock();
        const previousCooldown = cooldowns.get(key);

        // The first request after stage one either clears the user or escalates.
        if (previousCooldown && previousCooldown.stage === 1 && now >= previousCooldown.expiresAt) {
            if (decision.decision === "ALLOW") {
                cooldowns.delete(key);
                deniedAttempts.delete(key);
                stageOneAttempts.delete(key);
                return null;
            }

            if (decision.decision === "DENY") {
                const attempts = (stageOneAttempts.get(key) || [])
                    .filter(timestamp => now - timestamp <= windowMs);

                attempts.push(now);
                stageOneAttempts.set(key, attempts);

                if (attempts.length !== threshold) {
                    return null;
                }

                const expiresAt = now + stageTwoCooldownMs;
                cooldowns.set(key, { stage: 2, expiresAt });
                stageOneAttempts.delete(key);

                return {
                    timestamp: new Date(now).toISOString(),
                    type: "RATE_LIMIT_ESCALATED",
                    username: decision.user,
                    role: decision.role,
                    action: decision.action,
                    resource: decision.resource,
                    deniedAttemptCount: attempts.length,
                    cooldownSeconds: stageTwoCooldownMs / 1000,
                    rateLimitExpiresAt: new Date(expiresAt).toISOString(),
                    recommendation: "Repeated unauthorized activity after the grace period. One-hour rate limiting has been enabled."
                };
            }
        }

        if (decision.decision !== "DENY") {
            return null;
        }

        const attempts = (deniedAttempts.get(key) || [])
            .filter(timestamp => now - timestamp <= windowMs);

        attempts.push(now);
        deniedAttempts.set(key, attempts);

        if (attempts.length !== threshold) {
            return null;
        }

        const expiresAt = now + stageOneCooldownMs;
        cooldowns.set(key, { stage: 1, expiresAt });

        return {
            timestamp: new Date(now).toISOString(),
            type: "REPEATED_DENIAL",
            username: decision.user,
            role: decision.role,
            action: decision.action,
            resource: decision.resource,
            deniedAttemptCount: attempts.length,
            windowSeconds: windowMs / 1000,
            cooldownSeconds: stageOneCooldownMs / 1000,
            rateLimitExpiresAt: new Date(expiresAt).toISOString(),
            recommendation: "Review this account's recent authorization activity."
        };
    }

    return { recordDecision, getRateLimit };
}

const denialMonitor = createDenialMonitor();

function monitorAuthorizationDecision(decision) {
    const securityEvent = denialMonitor.recordDecision(decision);

    if (!securityEvent) {
        return null;
    }

    if (!fs.existsSync(logDirectory)) {
        fs.mkdirSync(logDirectory, { recursive: true });
    }

    fs.appendFileSync(securityEventFile, JSON.stringify(securityEvent) + "\n");
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
