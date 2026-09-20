import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import {
  EBPFDiagnosticsResponseSchema,
  EBPFInboundDiagnosticsSchema,
  type EBPFInboundDiagnostics,
} from "../gen/daemon/started_service_pb";
import {
  ebpfDiagnosticsJson,
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

  it("uses the response diagnostics schema version with an inbound fallback", () => {
    const current = create(EBPFDiagnosticsResponseSchema, {
      schemaVersion: 5,
      inbounds: [create(EBPFInboundDiagnosticsSchema, { schemaVersion: 3 })],
    });
    expect(ebpfDiagnosticsSchemaVersion(current)).toBe(5);

    const legacy = create(EBPFDiagnosticsResponseSchema, {
      inbounds: [
        create(EBPFInboundDiagnosticsSchema, { schemaVersion: 2 }),
        create(EBPFInboundDiagnosticsSchema, { schemaVersion: 3 }),
      ],
    });
    expect(ebpfDiagnosticsSchemaVersion(legacy)).toBe(3);
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
