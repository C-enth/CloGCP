import { afterEach, describe, expect, it, vi } from "vitest";
import { api, display, relativePaths } from "./api";

function reply(status: number, data: object) {
  return Promise.resolve({ ok: status < 300, json: async () => data });
}
const busy = { error: "WORKSPACE_OPERATION_IN_PROGRESS", message: "busy" };
describe("reads while a local job owns the database", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("waits and retries a read instead of failing", async () => {
    const fetch = vi
      .fn()
      .mockReturnValueOnce(reply(400, busy))
      .mockReturnValueOnce(reply(200, { items: [] }));
    vi.stubGlobal("fetch", fetch);
    await expect(api("/runs")).resolves.toEqual({ items: [] });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it("never retries a write", async () => {
    const fetch = vi.fn().mockReturnValue(reply(400, busy));
    vi.stubGlobal("fetch", fetch);
    await expect(api("/runs/x/review/y", {})).rejects.toThrow(
      "WORKSPACE_OPERATION_IN_PROGRESS",
    );
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
describe("bounded UI formatting and selection", () => {
  it("formats unresolved without inventing a PASS", () => {
    expect(display(null)).toBe("Unresolved");
    expect(display(["UNKNOWN"])).toBe('["UNKNOWN"]');
  });
  it("preserves nested paths while removing the selected package directory", () => {
    const files = [
      { name: "manifest.json", webkitRelativePath: "package/manifest.json" },
      { name: "x.json", webkitRelativePath: "package/roles/x.json" },
    ] as File[];
    expect(relativePaths(files)).toEqual(["manifest.json", "roles/x.json"]);
  });
  it("does not rewrite unrelated selections", () => {
    expect(
      relativePaths([{ name: "a.json" }, { name: "b.json" }] as File[]),
    ).toEqual(["a.json", "b.json"]);
  });
});
