import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 30_000, // bcrypt cost 12 is deliberately slow
    env: {
      NODE_ENV: "test",
      PORT: "3999",
      JWT_ACCESS_SECRET: "test-access-secret-test-access-secret-0123456789",
      JWT_REFRESH_SECRET: "test-refresh-secret-test-refresh-secret-987654321",
      CORS_ORIGINS: "http://localhost:5173,https://app.example.com",
      RATE_LIMIT_MAX: "100000",
      AUTH_RATE_LIMIT_MAX: "100000",
    },
  },
});
