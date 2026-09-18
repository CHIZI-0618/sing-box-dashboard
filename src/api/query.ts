import { useSyncExternalStore } from "react";

import { describeError } from "./stream";

export type QueryPhase = "idle" | "loading" | "loaded" | "error";

export interface QuerySnapshot<T> {
  phase: QueryPhase;
  data: T | null;
  error?: string;
  fetchedAt: number | null;
}

export class QueryStore<T> {
  private listeners = new Set<() => void>();
  private snapshot: QuerySnapshot<T> = { phase: "idle", data: null, fetchedAt: null };
  private controller: AbortController | null = null;
  private request: Promise<void> | null = null;

  constructor(private readonly query: (signal: AbortSignal) => Promise<T>) {}

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) {
        this.controller?.abort();
      }
    };
  };

  getSnapshot = (): QuerySnapshot<T> => this.snapshot;

  refresh = (): Promise<void> => {
    if (this.request !== null) {
      return this.request;
    }
    const controller = new AbortController();
    this.controller = controller;
    this.setSnapshot({ ...this.snapshot, phase: "loading", error: undefined });
    const request = this.query(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) {
          this.setSnapshot({ phase: "loaded", data, fetchedAt: Date.now() });
        }
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          this.setSnapshot({
            ...this.snapshot,
            phase: "error",
            error: describeError(error).message,
          });
        }
      })
      .finally(() => {
        if (this.controller === controller) {
          if (controller.signal.aborted) {
            this.setSnapshot({
              phase: this.snapshot.data === null ? "idle" : "loaded",
              data: this.snapshot.data,
              fetchedAt: this.snapshot.fetchedAt,
            });
          }
          this.controller = null;
        }
        if (this.request === request) {
          this.request = null;
        }
      });
    this.request = request;
    return request;
  };

  invalidate = (): void => {
    this.controller?.abort();
    this.controller = null;
    this.request = null;
    this.setSnapshot({ phase: "idle", data: null, fetchedAt: null });
  };

  private setSnapshot(next: QuerySnapshot<T>) {
    this.snapshot = next;
    for (const listener of this.listeners) {
      listener();
    }
  }
}

export function useQuery<T>(store: QueryStore<T>): QuerySnapshot<T> {
  return useSyncExternalStore(store.subscribe, store.getSnapshot);
}
