import { describe, expect, it, vi } from "vitest";

import { QueryStore } from "./query";

describe("QueryStore", () => {
  it("deduplicates requests and retains the successful snapshot while refreshing", async () => {
    let resolve: (value: number) => void = () => {};
    const query = vi.fn(
      () =>
        new Promise<number>((done) => {
          resolve = done;
        }),
    );
    const store = new QueryStore(query);
    const unsubscribe = store.subscribe(() => {});

    const first = store.refresh();
    const duplicate = store.refresh();
    expect(query).toHaveBeenCalledTimes(1);
    expect(duplicate).toBe(first);
    expect(store.getSnapshot()).toMatchObject({ phase: "loading", data: null });

    resolve(7);
    await first;
    expect(store.getSnapshot()).toMatchObject({ phase: "loaded", data: 7 });

    void store.refresh();
    expect(store.getSnapshot()).toMatchObject({ phase: "loading", data: 7 });
    unsubscribe();
  });

  it("keeps the last successful snapshot when refresh fails", async () => {
    let calls = 0;
    const store = new QueryStore(async () => {
      calls += 1;
      if (calls === 1) {
        return "healthy";
      }
      throw new Error("offline");
    });
    const unsubscribe = store.subscribe(() => {});

    await store.refresh();
    await store.refresh();
    expect(store.getSnapshot()).toMatchObject({
      phase: "error",
      data: "healthy",
      error: "offline",
    });
    unsubscribe();
  });

  it("aborts an unfinished request after the last subscriber leaves", async () => {
    let aborted = false;
    const store = new QueryStore<null>(
      (signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => {
            aborted = true;
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );
    const unsubscribe = store.subscribe(() => {});

    const request = store.refresh();
    unsubscribe();
    await request;
    expect(aborted).toBe(true);
    expect(store.getSnapshot().phase).toBe("idle");
  });

  it("invalidates cached data and cancels the active request", async () => {
    const store = new QueryStore<null>(() => new Promise(() => {}));
    const unsubscribe = store.subscribe(() => {});
    void store.refresh();

    store.invalidate();
    expect(store.getSnapshot()).toEqual({ phase: "idle", data: null, fetchedAt: null });
    unsubscribe();
  });
});
