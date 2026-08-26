// Type surface for fixture-session.mjs (plain ESM, run by both node
// harness scripts and imported by the Playwright spec).
export const SESSION_COOKIE_NAME: string;
export function fixtureSid(role: "admin" | "user"): string;
export function seedFixtureSessions(redisURL: string): Promise<void>;
