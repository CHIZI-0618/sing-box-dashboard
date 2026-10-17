import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import {
  EBPFDiagnosticsResponseSchema,
  EBPFInboundDiagnosticsSchema,
  type EBPFInboundDiagnostics,
} from "../gen/daemon/started_service_pb";
import {
  ebpfDiagnosticsJson,
  ebpfMapHealth,
  ebpfMapPressure,
  ebpfInboundHealth,
  ebpfTCDegradation,
  ebpfDiagnosticsSchemaVersion,
  ebpfStateTone,
  occupancyPercent,
  positiveCounterDelta,
  unixMillis,
  worstEBPFState,
} from "./ebpf";

function inbound(state: string): EBPFInboundDiagnostics {
  return { state } as EBPFInboundDiagnostics;
}

describe("eBPF diagnostics helpers", () => {
  it("does not report recovery when a deep pressure snapshot is followed by lightweight data", () => {
    const pressure = create(EBPFInboundDiagnosticsSchema, {
      state: "normal",
      kernelRuntime: { mapOccupancy: { status: "warning", maps: [{ entries: 9, maxEntries: 10, supported: true }] } },
    });
    const lightweight = create(EBPFInboundDiagnosticsSchema, { state: "normal" });
    const recovered = create(EBPFInboundDiagnosticsSchema, {
      state: "normal",
      kernelRuntime: { mapOccupancy: { status: "pass", maps: [{ entries: 2, maxEntries: 10, supported: true }] } },
    });
    expect(ebpfMapPressure(pressure.kernelRuntime)).toBe("high");
    expect(ebpfMapPressure(lightweight.kernelRuntime)).toBe("not_collected");
    expect([pressure, lightweight, recovered].map(ebpfInboundHealth)).toEqual(["map_pressure", "unverified", "healthy"]);
  });

  it("keeps failed, partial and unknown occupancy unverified", () => {
    for (const mapOccupancy of [
      { status: "unknown", maps: [] },
      { status: "pass", maps: [] },
      { status: "pass", maps: [{ supported: true, maxEntries: 0 }] },
      { status: "pass", error: "enumeration failed", maps: [] },
      { status: "pass", maps: [{ entries: 0, maxEntries: 10, supported: true, error: "lookup failed" }] },
      { status: "pass", maps: [{ supported: false, pressure: "unavailable" }] },
    ]) {
      const current = create(EBPFInboundDiagnosticsSchema, { state: "normal", kernelRuntime: { mapOccupancy } });
      expect(ebpfMapPressure(current.kernelRuntime)).toBe("unavailable");
      expect(ebpfInboundHealth(current)).toBe("unverified");
    }
  });

  it("retains lightweight pressure and real failures without requiring a deep scan", () => {
    expect(ebpfInboundHealth(create(EBPFInboundDiagnosticsSchema, { state: "normal", tcAssignmentSweepPressure: true }))).toBe("map_pressure");
    expect(ebpfInboundHealth(create(EBPFInboundDiagnosticsSchema, { state: "normal", tcRequiresRebuild: true }))).toBe("attachment_lost");
    expect(ebpfInboundHealth(create(EBPFInboundDiagnosticsSchema, { state: "recovering" }))).toBe("recovering");
  });

  it("does not classify configured or inapplicable maps as missing measurements", () => {
    const current = create(EBPFInboundDiagnosticsSchema, { state: "normal", kernelRuntime: { mapOccupancy: { status: "pass", maps: [
      { category: "configured_policy", supported: true, pressure: "configured", entries: 10, maxEntries: 10 },
      { supported: false, pressure: "not_applicable" },
    ] } } });
    expect(ebpfInboundHealth(current)).toBe("healthy");
  });
  it("keeps waiting interfaces neutral and surfaces recovery severity", () => {
    expect(ebpfStateTone("normal")).toBe("good");
    expect(ebpfStateTone("waiting_for_interface")).toBe("neutral");
    expect(ebpfStateTone("recovering")).toBe("medium");
    expect(ebpfStateTone("needs_attention")).toBe("bad");
    expect(ebpfStateTone("future_state")).toBe("neutral");
  });

  it("selects the worst state without treating unknown values as healthy", () => {
    expect(worstEBPFState([])).toBeNull();
    expect(worstEBPFState([inbound("normal"), inbound("recovering")])).toBe("recovering");
    expect(worstEBPFState([inbound("normal"), inbound("future_state")])).toBe("future_state");
    expect(worstEBPFState([inbound("future_state"), inbound("needs_attention")])).toBe(
      "needs_attention",
    );
  });

  it("computes bigint deltas without losing precision and resets on counter rollback", () => {
    const large = BigInt(Number.MAX_SAFE_INTEGER) + 100n;
    expect(positiveCounterDelta(large + 7n, large)).toBe(7n);
    expect(positiveCounterDelta(4n, 10n)).toBe(0n);
    expect(positiveCounterDelta(4n, undefined)).toBe(0n);
  });

  it("handles unsupported occupancy ratios and timestamps safely", () => {
    expect(occupancyPercent(1, 0)).toBeNull();
    expect(occupancyPercent(5, 10)).toBe(50);
    expect(occupancyPercent(20, 10)).toBe(100);
    expect(unixMillis(undefined)).toBeNull();
    expect(unixMillis(0n)).toBeNull();
    expect(unixMillis(1_700_000_000_000n)).toBe(1_700_000_000_000);
    expect(unixMillis(BigInt(Number.MAX_SAFE_INTEGER) + 1n)).toBeNull();
  });

  it("summarizes kernel map health without treating unsupported maps as full", () => {
    const runtime = create(EBPFDiagnosticsResponseSchema, {
      kernelRuntime: {
        mapOccupancy: {
          maps: [
            { entries: 9, maxEntries: 10, supported: true },
            { entries: 1, maxEntries: 10, supported: true },
            { entries: 10, maxEntries: 10, supported: true, category: "configured_policy", pressure: "configured" },
            { entries: 0, maxEntries: 0, supported: true, category: "runtime", pressure: "not_applicable" },
            { entries: 0, maxEntries: 0, supported: false, pressure: "recovery_failed" },
            { entries: 0, maxEntries: 10, supported: true, category: "configured_policy", pressure: "recovery_failed" },
            { entries: 0, maxEntries: 0, supported: false, category: "configured_policy", pressure: "not_applicable" },
          ],
        },
      },
    }).kernelRuntime;
    expect(ebpfMapHealth(runtime)).toEqual({
      total: 7,
      supported: 2,
      configured: 1,
      notApplicable: 2,
      unavailable: 2,
      high: 1,
    });
    expect(ebpfMapHealth(undefined)).toEqual({
      total: 0,
      supported: 0,
      configured: 0,
      notApplicable: 0,
      unavailable: 0,
      high: 0,
    });
  });

  it("reports TC degradation from deltas while retaining lifetime totals", () => {
    const previous = create(EBPFInboundDiagnosticsSchema, {
      state: "normal",
      counters: { tcAssignmentUpdateFailures: 4n },
    });
    const current = create(EBPFInboundDiagnosticsSchema, {
      state: "recovering",
      counters: { tcAssignmentUpdateFailures: 7n, rewriteFailures: 2n },
    });
    expect(ebpfTCDegradation(current, previous)).toEqual({
      failures: 9n,
      recentFailures: 5n,
      active: true,
    });
  });

  it("keeps return failures historical until their counters increase", () => {
    const previous = create(EBPFInboundDiagnosticsSchema, { state: "normal", counters: { tcReturnConflicts: 4n } });
    expect(ebpfTCDegradation(previous, previous)).toEqual({ failures: 4n, recentFailures: 0n, active: false });
    const current = create(EBPFInboundDiagnosticsSchema, { state: "normal", counters: { tcReturnConflicts: 5n, tcReturnLookupFailures: 1n } });
    expect(ebpfTCDegradation(current, previous)).toEqual({ failures: 6n, recentFailures: 2n, active: true });
  });

  it("uses the response diagnostics schema version", () => {
    const current = create(EBPFDiagnosticsResponseSchema, {
      schemaVersion: 14,
    });
    expect(ebpfDiagnosticsSchemaVersion(current)).toBe(14);

    expect(ebpfDiagnosticsSchemaVersion(create(EBPFDiagnosticsResponseSchema))).toBe(0);
  });

  it("exports bigint counters using protobuf JSON without precision loss", () => {
    const large = BigInt(Number.MAX_SAFE_INTEGER) + 123n;
    const diagnostics = create(EBPFDiagnosticsResponseSchema, {
      inbounds: [
        create(EBPFInboundDiagnosticsSchema, {
          tag: "ebpf-in",
          localBypassRuleSet: {
            policyVersion: large,
          },
        }),
      ],
    });
    const json = ebpfDiagnosticsJson(diagnostics);
    expect(JSON.parse(json)).toMatchObject({
      inbounds: [
        {
          tag: "ebpf-in",
          localBypassRuleSet: { policyVersion: large.toString() },
        },
      ],
    });
  });
});
