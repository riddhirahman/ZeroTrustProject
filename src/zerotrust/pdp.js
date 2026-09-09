// Policy Decision Point (PDP)
//
// The PDP decides whether an authenticated user
// is allowed to perform an action on a resource.

// Centralized authorization policy
const policies = {
    USER: {
        "/api/profile": ["GET"]
    },

    ADMIN: {
        "/api/profile": ["GET", "POST"],
        "/api/admin": ["GET"]
    }
};

function evaluatePolicy(user, resource, action) {

    const rolePolicies = policies[user.role];

    // Unknown role
    if (!rolePolicies) {
        return {
            user: user.username,
            role: user.role,
            action,
            resource,
            decision: "DENY",
            reason: "Unknown user role"
        };
    }

    const allowedActions = rolePolicies[resource];

    // Role has no policy for this resource
    if (!allowedActions) {
        return {
            user: user.username,
            role: user.role,
            action,
            resource,
            decision: "DENY",
            reason: `${user.role} is not permitted to access ${resource}`
        };
    }

    // Check whether requested action is allowed
    if (!allowedActions.includes(action)) {
        return {
            user: user.username,
            role: user.role,
            action,
            resource,
            decision: "DENY",
            reason: `${user.role} is not permitted to perform ${action} on ${resource}`
        };
    }

    // Policy matched
    return {
        user: user.username,
        role: user.role,
        action,
        resource,
        decision: "ALLOW",
        reason: `${user.role} is permitted to perform ${action} on ${resource}`
    };
}

module.exports = {
    evaluatePolicy
};