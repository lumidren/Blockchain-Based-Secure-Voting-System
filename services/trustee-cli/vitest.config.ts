import { defineConfig } from "vitest/config";

// Argon2id runs in pure JavaScript (@noble/hashes): each derivation takes ~0.5–1 s at the test cost.
export default defineConfig({ test: { include: ["test/**/*.test.ts"], testTimeout: 60_000 } });
