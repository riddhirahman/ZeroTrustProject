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

        // 2. Ask PDP for authorization decision
        const resource = req.originalUrl.split("?")[0];
        const action = req.method;

        const policyResult = evaluatePolicy(
            decoded,
            resource,
            action
        );

        console.log("[PDP]", {
            user: decoded.username,
            role: decoded.role,
            action: action,
            resource: resource,
            decision: policyResult.decision,
            reason: policyResult.reason
        });

        // 3. PEP enforces PDP decision
        if (policyResult.decision === "DENY") {
            return res.status(403).json(policyResult);
        }

        // 4. Request is allowed
        next();

    } catch (error) {
        return res.status(401).json({
            decision: "DENY",
            reason: "Invalid or expired token"
        });
    }
}

module.exports = pep;