// Real aw SSE frames, dispatched through the production channel-core consumer.
import { createInterface } from 'node:readline';
import { dispatchAgentEvent } from '../../channel-core/dist/index.js';
const dispatched = new Set();
for await (const line of createInterface({ input: process.stdin })) {
  const event = JSON.parse(line);
  if (event.type !== 'app_event') continue;
  await dispatchAgentEvent({ onAwakening: awakening => console.log(JSON.stringify(awakening)) }, dispatched, event);
}
