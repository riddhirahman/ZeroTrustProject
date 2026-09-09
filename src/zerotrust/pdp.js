// Policy Decision Point (PDP)
//
// The PDP decides whether an authenticated user
// is allowed to perform an action on a resource.

// Centralized authorization policy
const policies = {
    USER: {
        "/api/profile": ["GET", "POST"]
    },

    ADMIN: {
        "/api/profile": ["GET", "POST", "DELETE"],
        "/api/admin": ["GET"]
    }
};

function evaluatePolicy(user, action, resource) {

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

    // Check whether the role has access to the resource
    const allowedActions = rolePolicies[resource];

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

    // Check whether the requested action is allowed
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