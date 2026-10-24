import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
const version = readFileSync("../pyproject.toml", "utf8").match(
  /^version = "([^"]+)"/m,
)![1];
const hash = createHash("sha256");
for (const name of readdirSync("src").sort()) {
  if (/\.(tsx?|css)$/.test(name)) hash.update(readFileSync(`src/${name}`));
}
hash.update(version);
hash.update("local-jobs-1");
const build = {
  application_version: version,
  frontend_build_id: hash.digest("hex"),
  transport_version: "local-jobs-1",
};
export default defineConfig({
  define: { __CLOSEC_BUILD__: JSON.stringify(build) },
  plugins: [
    react(),
    {
      name: "closec-build-identity",
      closeBundle() {
        writeFileSync(
          "../src/offline_analyzer/api/assets/build-info.json",
          JSON.stringify(build),
        );
      },
    },
  ],
  build: { outDir: "../src/offline_analyzer/api/assets", emptyOutDir: true },
});
