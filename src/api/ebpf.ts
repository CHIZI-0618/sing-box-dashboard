import { toJsonString } from "@bufbuild/protobuf";

import type { EBPFInboundDiagnostics } from "../gen/daemon/started_service_pb";
import {
  EBPFDiagnosticsResponseSchema,
  type EBPFDiagnosticsResponse,
} from "../gen/daemon/started_service_pb";
import type { DelayTone } from "./format";

export const SUPPORTED_EBPF_SCHEMA_VERSION = 2;

export function ebpfDiagnosticsJson(diagnostics: EBPFDiagnosticsResponse): string {
  return toJsonString(EBPFDiagnosticsResponseSchema, diagnostics, {
    alwaysEmitImplicit: true,
    prettySpaces: 2,
  });
}

const STATE_RANK: Record<string, number> = {
  normal: 0,
  waiting_for_interface: 1,
  recovering: 2,
  needs_attention: 3,
};

export function ebpfStateTone(state: string): DelayTone {
  switch (state) {
    case "normal":
      return "good";
    case "recovering":
      return "medium";
    case "needs_attention":
      return "bad";
    default:
      return "neutral";
  }
}

export function worstEBPFState(inbounds: readonly EBPFInboundDiagnostics[]): string | null {
  let worst: string | null = null;
  let worstRank = -1;
  for (const inbound of inbounds) {
    const rank = STATE_RANK[inbound.state] ?? 1;
    if (rank > worstRank) {
      worst = inbound.state;
      worstRank = rank;
    }
  }
  return worst;
}

export function positiveCounterDelta(current: bigint, previous: bigint | undefined): bigint {
  if (previous === undefined || current < previous) {
    return 0n;
  }
  return current - previous;
}

export function occupancyPercent(entries: number, maxEntries: number): number | null {
  if (maxEntries <= 0 || entries < 0) {
    return null;
  }
  return Math.min(100, (entries / maxEntries) * 100);
}

export function unixMillis(value: bigint | undefined): number | null {
  if (value === undefined || value <= 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    return null;
  }
  return Number(value);
}
