# Security policy

## Supported versions

Security fixes are currently made on the `main` branch.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** action in the repository Security tab for private disclosure. Do not include private keys, personal files, or exploitable details in a public issue. Include affected versions, impact, and reproducible steps where possible.

## Deployment guidance

- Never put wallet private keys in the API, web app, Docker image, issue, or commit. The deployer key is only for contract deployment and belongs in an ignored local env file or a host secret manager.
- Use a Safe/multisig for registry administration and a separate throwaway deployer for testnet deployment.
- Set a unique `AUTH_TOKEN_SECRET`; use HTTPS and configure trusted proxy addresses before enabling proxy headers.
- Keep PostgreSQL and Redis private to the application network. Rate limiting is per-process unless shared Redis is configured.
- Treat file analysis as advisory. The scanner is not antivirus, and model outputs do not prove authenticity.
