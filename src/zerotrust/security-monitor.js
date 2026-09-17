const fs = require("fs");
const path = require("path");

const logDirectory = path.join(__dirname, "../../logs");
const securityEventFile = path.join(logDirectory, "security-events.log");

function createDenialMonitor({
    threshold = 3,
    windowMs = 5 * 60 * 1000,
    clock = () => Date.now()
} = {}) {
    const deniedAttempts = new Map();

    function recordDecision(decision) {
        if (decision.decision !== "DENY") {
            return null;
        }

        const key = `${decision.user}|${decision.role}|${decision.resource}`;
        const now = clock();
        const attempts = (deniedAttempts.get(key) || [])
            .filter(timestamp => now - timestamp <= windowMs);

        attempts.push(now);
        deniedAttempts.set(key, attempts);

        if (attempts.length !== threshold) {
            return null;
        }

        return {
            timestamp: new Date(now).toISOString(),
            type: "REPEATED_DENIAL",
            username: decision.user,
            role: decision.role,
            action: decision.action,
            resource: decision.resource,
            deniedAttemptCount: attempts.length,
            windowSeconds: windowMs / 1000,
            recommendation: "Review this account's recent authorization activity."
        };
    }

    return { recordDecision };
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

module.exports = {
    createDenialMonitor,
    monitorAuthorizationDecision
};
