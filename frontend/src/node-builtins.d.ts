// Minimal declarations for the Node built-ins used by the trusted Vite build recipe.
declare module "node:crypto" {
  type Hash = {
    update(data: string | Uint8Array): Hash;
    digest(encoding: "hex"): string;
  };
  export function createHash(algorithm: "sha256"): Hash;
}
declare module "node:fs" {
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function readFileSync(path: string): Uint8Array;
  export function readdirSync(path: string): string[];
  export function writeFileSync(path: string, data: string): void;
}
