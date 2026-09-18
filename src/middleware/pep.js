const { auditLog } = require("../zerotrust/audit"); //Require the auditLog function from the audit.js file
const {
    getRateLimit,
    monitorAuthorizationDecision
} = require("../zerotrust/security-monitor");
const jwt = require("jsonwebtoken");
const { evaluatePolicy } = require("../zerotrust/pdp");

function pep(req, res, next) {
    const authHeader = req.headers.authorization;

    // No token
    if (!authHeader) {
        return res.status(401).json({
            decision: "DENY",
            reason: "No authorization token provided"
        });
    }

    const token = authHeader.split(" ")[1];

    // Invalid format
    if (!token) {
        return res.status(401).json({
            decision: "DENY",
            reason: "Invalid authorization format"
        });
    }

    try {
        // 1. Verify identity/session
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = decoded;

        console.log("[PEP] Identity verified:", {
            username: decoded.username,
            role: decoded.role
        });

        // 2. Identify the requested resource and action.
        const resource = req.originalUrl.split("?")[0];
        const action = req.method;

        // 3. Block repeated denied attempts before they reach the PDP.
        const rateLimit = getRateLimit({
            user: decoded.username,
            role: decoded.role,
            resource
        });
        if (rateLimit) {
            res.set("Retry-After", String(rateLimit.retryAfterSeconds));
            return res.status(429).json({
                decision: "RATE_LIMITED",
                reason: "You are being rate limited due to repeated unauthorized requests. Please try again later.",
                rateLimitStage: rateLimit.stage,
                retryAfterSeconds: rateLimit.retryAfterSeconds
            });
        }

        // 4. Ask PDP for authorization decision.
        const policyResult = evaluatePolicy(
            decoded,
            action,
            resource
        );

        console.log("[PDP]", policyResult);

        // 5. Record authorization decision.
        auditLog(policyResult);

        // 6. Detect repeated denied attempts and enable temporary rate limiting.
        const securityEvent = monitorAuthorizationDecision(policyResult);
        if (securityEvent) {
            console.warn("[Security Monitor]", securityEvent);
        }

        // 7. PEP enforces PDP decision.
        if (policyResult.decision === "DENY") {
            return res.status(403).json(policyResult);
        }

        // 8. Request is allowed.
        return next();

    } catch (error) {
        return res.status(401).json({
            decision: "DENY",
            reason: "Invalid or expired token"
        });
    }
}

module.exports = pep;
