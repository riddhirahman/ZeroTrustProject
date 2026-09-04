// Policy Decision Point (PDP)
//
// The PDP decides whether an authenticated user
// is allowed to access a requested resource.

function evaluatePolicy(user, resource) {

    // USER permissions
    if (user.role === "USER") {
        if (resource === "/api/profile") {
            return {
                decision: "ALLOW",
                reason: "USER is permitted to access profile"
            };
        }

        return {
            decision: "DENY",
            reason: "USER does not have permission for this resource"
        };
    }

    // ADMIN permissions
    if (user.role === "ADMIN") {
        if (
            resource === "/api/profile" ||
            resource === "/api/admin"
        ) {
            return {
                decision: "ALLOW",
                reason: "ADMIN is permitted to access this resource"
            };
        }

        return {
            decision: "DENY",
            reason: "ADMIN does not have permission for this resource"
        };
    }

    // Unknown role
    return {
        decision: "DENY",
        reason: "Unknown user role"
    };
}

module.exports = {
    evaluatePolicy
};