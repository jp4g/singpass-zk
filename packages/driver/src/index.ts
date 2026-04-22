import { startMockpass, stopMockpass } from "./spawn.ts";
import { isReady } from "./health.ts";
import { DISCOVERY_URL, LOG_FILE, MOCKPASS_BASE } from "./paths.ts";

const cmd = process.argv[2];

async function main() {
  switch (cmd) {
    case "up": {
      const pid = await startMockpass();
      console.log(`MockPass up. pid=${pid}`);
      console.log(`  base:      ${MOCKPASS_BASE}`);
      console.log(`  discovery: ${DISCOVERY_URL}`);
      console.log(`  logs:      ${LOG_FILE}`);
      break;
    }
    case "down": {
      const stopped = await stopMockpass();
      console.log(stopped ? "MockPass stopped." : "No MockPass PID file found.");
      break;
    }
    case "status": {
      const ready = await isReady();
      console.log(ready ? "MockPass: UP" : "MockPass: DOWN");
      process.exit(ready ? 0 : 1);
    }
    default:
      console.error(`usage: driver <up|down|status>`);
      process.exit(2);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
