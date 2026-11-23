# Contributing

Thanks for considering a contribution to ProofChain.

## Development setup

Follow the local setup in [`proofchain/README.md`](proofchain/README.md). Run the relevant checks before opening a pull request:

```sh
cd proofchain/contracts && npx hardhat test
cd proofchain/backend && python -m pytest -q
cd proofchain/frontend && npm run build
```

## Pull requests

- Keep changes focused and explain the behavior they change.
- Add or update tests for behavior changes.
- Document new environment variables in the matching `.env.example` file.
- Never commit `.env` files, private keys, model weights, uploaded files, or generated deployment secrets.
- Update the README when a user-facing flow, deployment step, or known limitation changes.

## Reporting bugs

Use the bug report issue form and include reproducible steps, expected behavior, actual behavior, and relevant logs with secrets removed.
