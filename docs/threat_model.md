# Threat model

Primary controls: protocol allowlist; local, loopback, link-local, private and reserved IP rejection; metadata hostname rejection; credential rejection; no DNS resolution; no outbound target requests; body-size limit; CORS allowlist; rate limiting; content security policy; and no raw exception responses.

DNS rebinding is avoided by deliberately not resolving target hostnames. Deployment should add reverse-proxy TLS/HSTS, production CSP tuning, database backups, authentication/authorization and central audit retention policy.
