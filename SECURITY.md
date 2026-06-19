# Security Policy

## Authorized Use

This project is designed for defensive, authorized OSINT and cyber investigation work.

The engine is passive by default. Any active collection, probing, scanning, or scope-expanding enrichment must only be run against assets you own or are explicitly authorized to assess.

## Secrets

Keep API keys and local credentials in `.env`. The `.env` file is intentionally ignored by Git.

Do not commit:

- API keys
- Neo4j passwords
- Raw investigation logs containing sensitive targets
- Generated reports from private investigations

## Reporting Issues

If you find a security issue in the project itself, open a private report or contact the repository owner before publishing details.

Please include:

- A short description of the issue
- Steps to reproduce
- Expected and actual behavior
- Whether any secret or sensitive output was exposed
