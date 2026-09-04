// Policy Decision Point (PDP)
//
// The PDP decides whether an authenticated user
// is allowed to perform an action on a requested resource.

function evaluatePolicy(user, resource, action) {

    // USER permissions
    if (user.role === "USER") {

        if (
            resource === "/api/profile" &&
            action === "GET"
        ) {
            return {
                decision: "ALLOW",
                reason: "USER is permitted to perform GET on profile"
            };
        }

        return {
            decision: "DENY",
            reason: "USER is not permitted to perform this action on this resource"
        };
    }

    // ADMIN permissions
    if (user.role === "ADMIN") {

        if (
            resource === "/api/profile" &&
            action === "GET"
        ) {
            return {
                decision: "ALLOW",
                reason: "ADMIN is permitted to perform GET on profile"
            };
        }

        if (
            resource === "/api/admin" &&
            action === "GET"
        ) {
            return {
                decision: "ALLOW",
                reason: "ADMIN is permitted to perform GET on admin resource"
            };
        }

        return {
            decision: "DENY",
            reason: "ADMIN is not permitted to perform this action on this resource"
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