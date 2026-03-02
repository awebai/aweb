import { Client, GatewayIntentBits, Partials, type TextChannel } from "discord.js";
import Redis from "ioredis";
import { config } from "./config.js";
import { SessionMap } from "./session-map.js";
import { getWebhook, loadGuildMembers } from "./discord-sender.js";
import { startRedisListener, setOrdisWebhookConfig } from "./redis-listener.js";
import { startDiscordListener } from "./discord-listener.js";
import { startOrchestratorRelay } from "./orchestrator-relay.js";
import { startAiRelay } from "./ai-relay.js";
import { getOrCreateBridgeIdentity } from "./beadhub-client.js";

async function main(): Promise<void> {
  console.log("[bridge] Starting Discord Bridge for BeadHub...");

  // 1. Connect to Redis
  const redis = new Redis(config.redis.url);
  redis.on("error", (err) => console.error("[redis] Connection error:", err.message));
  await redis.ping();
  console.log("[redis] Connected");

  const sessionMap = new SessionMap(redis);

  // 2. Connect Discord client
  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMembers,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
    ],
    partials: [Partials.Message, Partials.Channel, Partials.Thread],
  });

  await client.login(config.discord.token);
  console.log(`[discord] Logged in as ${client.user?.tag}`);

  // 3. Load guild members for @mentions
  await loadGuildMembers(client);

  // 4. Get the target channel
  const channel = await client.channels.fetch(config.discord.channelId);
  if (!channel || !channel.isTextBased() || channel.isDMBased()) {
    throw new Error(`Channel ${config.discord.channelId} is not a guild text channel`);
  }
  const textChannel = channel as TextChannel;
  console.log(`[discord] Target channel: #${textChannel.name}`);

  // 4. Set up webhook client from pre-configured URL
  const webhook = getWebhook();

  // 5. Get/create bridge identity in BeadHub (for human relay)
  const bridgeIdentity = await getOrCreateBridgeIdentity();
  console.log(`[beadhub] Bridge identity: ${bridgeIdentity.alias} (${bridgeIdentity.workspace_id})`);

  // 6. Start Redis → Discord listener
  await startRedisListener(
    redis,
    textChannel,
    webhook,
    sessionMap,
    config.echoSuppressionTtlMs,
    bridgeIdentity.alias,
  );

  // 6b. Configure ordis webhook for control-plane messages → #ordis channel
  if (config.discord.ordisWebhookUrl && config.controlPlane.projectId) {
    setOrdisWebhookConfig({
      webhookUrl: config.discord.ordisWebhookUrl,
      controlPlaneProjectId: config.controlPlane.projectId,
    });
    console.log(`[bridge] Ordis channel routing enabled (project: ${config.controlPlane.projectId})`);
  }

  // 7. Start Discord → BeadHub + orchestrator listener
  startDiscordListener(client, sessionMap, bridgeIdentity, redis);

  // 8. Start agent outbox → Discord relay (orchestrator:outbox + agent:outbox)
  await startOrchestratorRelay(redis, textChannel, webhook, client);

  // 9. Start AI outbox → Discord relay (if AI channel configured)
  if (config.discord.aiChannelId && config.discord.aiWebhookUrl) {
    const aiChannel = await client.channels.fetch(config.discord.aiChannelId);
    if (aiChannel && aiChannel.isTextBased() && !aiChannel.isDMBased()) {
      const { WebhookClient } = await import("discord.js");
      const aiWebhook = new WebhookClient({ url: config.discord.aiWebhookUrl });
      await startAiRelay(redis, aiChannel as TextChannel, aiWebhook);
      console.log(`[bridge] AI relay started for #${(aiChannel as TextChannel).name}`);
    } else {
      console.warn(`[bridge] AI channel ${config.discord.aiChannelId} is not a valid text channel`);
    }
  }

  // 10. Health check server
  const healthServer = Bun.serve({
    port: config.health.port,
    fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/healthz") {
        const healthy = redis.status === "ready" && client.ws.status === 0;
        return new Response(
          JSON.stringify({ ok: healthy, redis: redis.status, discord: client.ws.status }),
          {
            status: healthy ? 200 : 503,
            headers: { "Content-Type": "application/json" },
          },
        );
      }
      return new Response("Not Found", { status: 404 });
    },
  });

  console.log(`[health] Listening on :${healthServer.port}/healthz`);
  console.log("[bridge] Ready — relaying BeadHub chat ↔ Discord");

  // Graceful shutdown
  const shutdown = async () => {
    console.log("[bridge] Shutting down...");
    healthServer.stop();
    client.destroy();
    redis.disconnect();
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  console.error("[bridge] Fatal error:", err);
  process.exit(1);
});
