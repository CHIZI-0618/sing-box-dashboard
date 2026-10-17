import { toJsonString } from "@bufbuild/protobuf";

import type {
  EBPFCounters,
  EBPFInboundDiagnostics,
  EBPFKernelRuntimeDiagnostics,
} from "../gen/daemon/started_service_pb";
import {
  EBPFDiagnosticsResponseSchema,
  type EBPFDiagnosticsResponse,
} from "../gen/daemon/started_service_pb";
import type { DelayTone } from "./format";

export const SUPPORTED_EBPF_SCHEMA_VERSION = 17;

export function ebpfDiagnosticsSchemaVersion(diagnostics: EBPFDiagnosticsResponse): number {
  return diagnostics.schemaVersion;
}

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

const TC_DEGRADATION_COUNTERS: (keyof EBPFCounters)[] = [
  "tcSocketLookupFailures",
  "tcSKAssignFailures",
  "tcAssignmentUpdateFailures",
  "tcReturnUpdateFailures",
  "tcReturnConflicts",
  "tcReturnLookupFailures",
  "rewriteFailures",
  "sharedReconcileFailures",
  "recoveryFailures",
];

export interface EBPFTCDegradation {
  failures: bigint;
  recentFailures: bigint;
  active: boolean;
}

/** Summarize TC/kernel degradation without treating lifetime counters as a new event. */
export function ebpfTCDegradation(
  inbound: EBPFInboundDiagnostics,
  previous?: EBPFInboundDiagnostics,
): EBPFTCDegradation {
  const counters = inbound.counters;
  const previousCounters = previous?.counters;
  let failures = 0n;
  let recentFailures = 0n;
  for (const key of TC_DEGRADATION_COUNTERS) {
    const current = (counters?.[key] as bigint | undefined) ?? 0n;
    failures += current;
    recentFailures += positiveCounterDelta(current, previousCounters?.[key] as bigint | undefined);
  }
  return {
    failures,
    recentFailures,
    active:
      recentFailures > 0n ||
      inbound.tcRequiresRebuild ||
      inbound.state === "recovering" ||
      inbound.state === "needs_attention",
  };
}

export function occupancyPercent(entries: number, maxEntries: number): number | null {
  if (maxEntries <= 0 || entries < 0) {
    return null;
  }
  return Math.min(100, (entries / maxEntries) * 100);
}

export interface EBPFMapHealth {
  total: number;
  supported: number;
  configured: number;
  notApplicable: number;
  unavailable: number;
  high: number;
}

export function ebpfMapHealth(runtime: EBPFKernelRuntimeDiagnostics | undefined): EBPFMapHealth {
  const maps = runtime?.mapOccupancy?.maps ?? [];
  let supported = 0;
  let configured = 0;
  let notApplicable = 0;
  let unavailable = 0;
  let high = 0;
  for (const map of maps) {
    if (map.error !== "" || map.pressure === "recovery_failed") {
      unavailable++;
      continue;
    }
    if (map.pressure === "not_applicable") {
      notApplicable++;
      continue;
    }
    if (!map.supported || map.maxEntries === 0) {
      // Unsupported maps with any status other than not_applicable represent
      // an actual inability to collect occupancy and remain actionable.
      unavailable++;
      continue;
    }
    if (map.category === "configured_policy") {
      configured++;
      continue;
    }
    supported++;
    const percent = occupancyPercent(map.entries, map.maxEntries);
    if (percent !== null && percent >= 85) {
      high++;
    }
  }
  return { total: maps.length, supported, configured, notApplicable, unavailable, high };
}

export type EBPFMapPressure = "high" | "clear" | "not_collected" | "unavailable";

/** Missing or failed measurements never prove that a previous pressure cleared. */
export function ebpfMapPressure(runtime: EBPFKernelRuntimeDiagnostics | undefined): EBPFMapPressure {
  const occupancy = runtime?.mapOccupancy;
  if (occupancy === undefined) return "not_collected";
  const health = ebpfMapHealth(runtime);
  if (health.high > 0) return "high";
  if (occupancy.error !== "" || health.total === 0 || health.unavailable > 0 ||
      !["pass", "warning", "degraded"].includes(occupancy.status)) return "unavailable";
  return "clear";
}

export type EBPFHealthKind =
  | "healthy"
  | "unverified"
  | "degraded"
  | "recovering"
  | "policy_pending"
  | "attachment_lost"
  | "map_pressure"
  | "udp_recovery_failed";

export function ebpfInboundHealth(inbound: EBPFInboundDiagnostics): EBPFHealthKind {
  if (inbound.recoveryUnrecoverable || inbound.localUdpState === "recovery_degraded") {
    return inbound.localUdpState === "recovery_degraded" ? "udp_recovery_failed" : "attachment_lost";
  }
  if (inbound.tcRequiresRebuild || inbound.tcHealthStatus === "lost") return "attachment_lost";
  if (inbound.recoveryPending || inbound.state === "recovering") return "recovering";
  if (inbound.localBypassRuleSet?.pending || inbound.sharedBypassRuleSet?.pending ||
      (inbound.policyEpoch !== undefined && !inbound.policyEpoch.converged)) return "policy_pending";
  const pressure = ebpfMapPressure(inbound.kernelRuntime);
  if (pressure === "high" || inbound.tcAssignmentSweepPressure || inbound.localUdpState === "map_pressure") return "map_pressure";
  if (inbound.state !== "normal" || inbound.localUdpState === "timeout_fallback" ||
      inbound.localUdpState === "release_notification") return "degraded";
  return pressure === "clear" ? "healthy" : "unverified";
}

export function unixMillis(value: bigint | undefined): number | null {
  if (value === undefined || value <= 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    return null;
  }
  return Number(value);
}
