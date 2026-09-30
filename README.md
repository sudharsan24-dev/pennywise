# Pennywise

A personal expense tracker built with **React, Node.js, Express and MySQL**. Track income and expenses, set a monthly budget and understand spending through category reports.

## Features

- Registration, login and private cookie sessions with scrypt password hashing.
- Add, edit and delete income and expense transactions.
- Monthly balance, income, expense and category summaries calculated in SQL.
- Monthly budgets with progress and overspending feedback.
- Month, transaction type and text filters; CSV export.
- Isolated demo workspace with fictional sample data.
- Responsive layout for desktop and mobile.
- Integer minor units (paise) avoid floating-point money arithmetic.
- Eleven HTTP integration tests against real MySQL, plus a GitHub Actions workflow.

## Run locally

Requires Node.js 24, pnpm 11 and MySQL 8.4. This app uses MySQL directly; there is no SQLite fallback.

Create a database and an app account using your MySQL administrator:

```sql
CREATE DATABASE pennywise CHARACTER SET utf8mb4;
CREATE USER 'pennywise'@'localhost' IDENTIFIED BY 'choose-a-strong-local-password';
GRANT ALL PRIVILEGES ON pennywise.* TO 'pennywise'@'localhost';
```

Copy `.env.example` to `.env` and enter your database settings. Never commit `.env`.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm start
```

Open http://localhost:5174 and select **Explore a private demo**, or create an account. Tables are created automatically on startup. Rebuild after frontend changes. `pnpm dev` starts the API and serves the latest build.

## Test

Point the environment variables at a dedicated test database, then run `pnpm test`. To load a local `.env` explicitly:

```sh
node --env-file=.env --test --test-concurrency=1 test/api.test.js
```

Tests create unique accounts and clean up their own records. They verify exact money totals, month boundaries, validation, editing, deletion, budget upserts, session invalidation, cross-origin protection and isolation between accounts. Local verification used MySQL 8.4.11 with all 11 tests passing. The CI workflow provisions MySQL 8.4 and runs tests plus a production build.

## Structure

```text
src/          React interface and responsive styles
server/       Express routes, authentication and MySQL schema
test/         HTTP integration tests
.github/      Automated MySQL tests and build
```

## Design decisions

Amounts enter the API as decimal strings and are stored as integer paise. Parameterized SQL prevents values from becoming SQL syntax. Every financial query includes the authenticated user's ID. Session tokens are opaque random values; only their hashes are stored in MySQL. Demo accounts are removed after seven days when another demo is created.

This is a portfolio application with manual entries, not a bank integration. INR is the only currency. Password reset, email verification, recurring entries and multi-currency accounting are future work. For an internet deployment, use HTTPS, `NODE_ENV=production`, an exact `APP_ORIGIN`, secret-managed database credentials, and persistent database backups.
