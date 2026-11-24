import { startServer } from "./lib/server.mjs";

const DEFAULT_PORT = 3494;

let starting;
let service = null;

function portOf(options) {
  const port = Number(options?.port ?? DEFAULT_PORT);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : DEFAULT_PORT;
}

export const __testing = {
  get starting() {
    return starting;
  },
  get service() {
    return service;
  },
  reset() {
    starting = undefined;
    service = null;
  },
};

export default {
  id: "magpie-simple-share",
  server: async (input = {}, options = {}) => {
    starting ??= startServer({
      port: portOf(options),
      portRetryMs: Number.POSITIVE_INFINITY,
      client: input.client,
      magpie: input.magpie,
      pluginInput: input,
    })
      .then((started) => {
        service = started;
        console.log(`[simple-share] listening on http://127.0.0.1:${started.port}`);
        return started;
      })
      .catch((error) => {
        starting = undefined;
        console.error(`[simple-share] service failed to start: ${String(error?.message ?? error)}`);
        return null;
      });
    return {};
  },
};
