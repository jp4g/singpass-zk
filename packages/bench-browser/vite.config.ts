import { defineConfig, type Plugin, type PluginOption } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import copy from "rollup-plugin-copy";
import {
  runOidcFlow,
  isMockpassReady,
  serialize,
} from "@singpass-zk/rp";

export default defineConfig({
  plugins: [
    copy({
      targets: [
        {
          src: "node_modules/**/*.wasm",
          dest: "node_modules/.vite/dist",
        },
      ],
      copySync: true,
      hook: "buildStart",
    }) as PluginOption,
    nodePolyfills(),
    wasmMime(),
    coopCoep(),
    oidcMiddleware(),
  ],
  server: {
    headers: {
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin",
    },
  },
  build: {
    target: "esnext",
    rollupOptions: { external: ["@aztec/bb.js"] },
  },
  // bb.js + noir_js bundle their own Web Workers and WASM. Vite's prebundling
  // breaks the worker URLs (`/node_modules/.vite/deps/main.worker.js?worker_file`
  // 404s); excluding them makes Vite serve them as raw ESM from node_modules
  // so the worker imports resolve relative to the bb.js sources.
  optimizeDeps: {
    exclude: ["@aztec/bb.js", "@noir-lang/noir_js"],
    esbuildOptions: { target: "esnext" },
  },
  worker: { format: "es" },
});

function oidcMiddleware(): Plugin {
  return {
    name: "singpass-oidc",
    configureServer(server) {
      server.middlewares.use("/api/oidc", async (_req, res) => {
        try {
          if (!(await isMockpassReady())) {
            res.statusCode = 503;
            res.setHeader("content-type", "application/json");
            res.end(
              JSON.stringify({
                error:
                  "MockPass is not running. Run `bun run driver:up` from the repo root.",
              }),
            );
            return;
          }
          const verified = await runOidcFlow();
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify(serialize(verified)));
        } catch (e) {
          res.statusCode = 500;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ error: String(e) }));
        }
      });
    },
  };
}

// Serve .wasm with the right MIME so browsers stream-instantiate. Vite's
// dev server otherwise hands them out as application/octet-stream.
function wasmMime(): Plugin {
  return {
    name: "wasm-mime",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.endsWith(".wasm")) {
          res.setHeader("content-type", "application/wasm");
        }
        next();
      });
    },
  };
}

// COOP/COEP headers are required for SharedArrayBuffer, which bb.js needs
// for multi-threaded WASM proving.
function coopCoep(): Plugin {
  return {
    name: "coop-coep",
    configureServer(server) {
      server.middlewares.use((_req, res, next) => {
        res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        next();
      });
    },
  };
}

