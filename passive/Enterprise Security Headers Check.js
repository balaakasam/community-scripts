// Passive scan rules should not make any requests
// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

const ScanRuleMetadata = Java.type(
    "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
        id: 110001
        name: Enterprise Security Headers Check
        description: >
            Checks for missing or misconfigured HTTP security headers commonly required
            in enterprise web application deployments. Covers headers that protect against
            clickjacking, MIME sniffing, cross-site scripting, and insecure transport.
        solution: >
            Ensure the following security headers are present in all HTTP responses:
            Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
            X-Content-Type-Options, and Referrer-Policy.
        references:
            - https://owasp.org/www-project-secure-headers/
            - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security
        risk: MEDIUM
        confidence: HIGH
        cweId: 693
        wascId: 15
        status: alpha
    `);
}

/**
 * Passively scans an HTTP message for missing enterprise security headers.
 *
 * @param ps - the PassiveScan parent object (PassiveScriptHelper)
 * @param msg - the HTTP Message being scanned (HttpMessage)
 * @param src - the Jericho Source representation of the message
 */
function scan(ps, msg, src) {
    // Only scan responses, not requests
    if (msg.getResponseHeader().isEmpty()) {
        return;
    }

    // Only scan HTML responses
    var contentType = msg.getResponseHeader().getHeader("Content-Type");
    if (!contentType || !contentType.toLowerCase().includes("text/html")) {
        return;
    }

    var responseHeader = msg.getResponseHeader();

    var securityHeaders = [
        {
            header: "Strict-Transport-Security",
            description:
                "Missing Strict-Transport-Security header. This header enforces HTTPS and protects against protocol downgrade attacks.",
            solution:
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
        },
        {
            header: "Content-Security-Policy",
            description:
                "Missing Content-Security-Policy header. This header helps prevent XSS and data injection attacks.",
            solution:
                "Define a Content-Security-Policy header appropriate for your application.",
        },
        {
            header: "X-Frame-Options",
            description:
                "Missing X-Frame-Options header. This header protects against clickjacking attacks.",
            solution:
                "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to HTTP responses.",
        },
        {
            header: "X-Content-Type-Options",
            description:
                "Missing X-Content-Type-Options header. This header prevents MIME type sniffing.",
            solution: "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
        },
        {
            header: "Referrer-Policy",
            description:
                "Missing Referrer-Policy header. This header controls how much referrer information is included with requests.",
            solution:
                "Add 'Referrer-Policy: strict-origin-when-cross-origin' or a stricter policy to HTTP responses.",
        },
    ];

    securityHeaders.forEach(function (item) {
        if (!responseHeader.getHeader(item.header)) {
            ps.newAlert()
                .setName("Missing " + item.header + " Header")
                .setRisk(ps.RISK_MEDIUM)
                .setConfidence(ps.CONFIDENCE_HIGH)
                .setDescription(item.description)
                .setSolution(item.solution)
                .setEvidence("Header '" + item.header + "' not found in response")
                .setCweId(693)
                .setWascId(15)
                .raise();
        }
    });
}

/**
 * Determines if the script applies to a given history type.
 *
 * @param histType - the history type to check
 * @returns true if the script should scan this history type
 */
function appliesToHistoryType(histType) {
    return histType === 1; // TYPE_PROXIED
}
