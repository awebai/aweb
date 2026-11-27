/** Keep the runner's tools, but never its aweb identity or delivery policy. */
export function childEnvironment(overrides: NodeJS.ProcessEnv = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith("AWEB_") && value !== undefined) env[key] = value;
  }
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  return env;
}
