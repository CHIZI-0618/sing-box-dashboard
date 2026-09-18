import { useEffect, useRef, type ReactNode } from "react";

import {
  SUPPORTED_EBPF_SCHEMA_VERSION,
  ebpfDiagnosticsJson,
  ebpfStateTone,
  occupancyPercent,
  positiveCounterDelta,
  unixMillis,
  worstEBPFState,
} from "../api/ebpf";
import { formatDateTime } from "../api/format";
import { useQuery } from "../api/query";
import { useApi } from "../app/context";
import { showError } from "../app/errorStore";
import { useI18n, type Translate } from "../app/i18n";
import { Icon } from "../components/Icon";
import {
  Badge,
  Button,
  Card,
  DataLine,
  EmptyState,
  IconButton,
  Spinner,
  StateDot,
} from "../components/ui";
import type {
  EBPFCounters,
  EBPFDiagnosticsResponse,
  EBPFInboundDiagnostics,
  EBPFKernelRuntimeDiagnostics,
  EBPFMapDiagnostics,
} from "../gen/daemon/started_service_pb";
import { ToolsPageHeader } from "./ToolsView";
import styles from "./EBPFView.module.css";

type CounterKey = keyof Omit<EBPFCounters, "$typeName" | "$unknown">;

const FAILURE_COUNTERS: CounterKey[] = [
  "assignmentLookupFailures",
  "tcSocketLookupFailures",
  "tcSKAssignFailures",
  "tcAssignmentUpdateFailures",
  "tokenReservationFailures",
  "rewriteFailures",
  "sharedReconcileFailures",
  "recoveryFailures",
  "fakeIPICMPRewriteFailureDrops",
];

const ACTIVITY_COUNTERS: CounterKey[] = [
  "tcLocalFragmentPasses",
  "tcSharedFragmentPasses",
  "sharedIngressPasses",
  "sharedEgressPasses",
  "sharedIngressFragmentPasses",
  "sharedEgressFragmentPasses",
  "recoveryAttempts",
  "recoverySuccesses",
  "fakeIPICMPReplies",
  "fakeIPICMPPassThrough",
];

export function EBPFView() {
  const api = useApi();
  const { t, language } = useI18n();
  const diagnostics = useQuery(api.ebpfDiagnostics);
  const previousInbounds = useRef(new Map<string, EBPFInboundDiagnostics>());

  useEffect(() => {
    void api.ebpfDiagnostics.refresh();
    return () => api.ebpfDiagnostics.invalidate();
  }, [api]);

  const data = diagnostics.data;
  const previous = previousInbounds.current;
  useEffect(() => {
    if (diagnostics.phase === "loaded" && data !== null) {
      previousInbounds.current = new Map(data.inbounds.map((inbound) => [inbound.tag, inbound]));
    }
  }, [data, diagnostics.phase]);

  return (
    <div className="page">
      <ToolsPageHeader
        title={t("eBPF Diagnostics")}
        actions={
          <div className={styles.headerActions}>
            {data !== null && (
              <IconButton
                title={t("Copy diagnostics JSON")}
                aria-label={t("Copy diagnostics JSON")}
                onClick={() => {
                  void navigator.clipboard
                    .writeText(ebpfDiagnosticsJson(data))
                    .catch(showError);
                }}
              >
                <Icon name="content_copy" />
              </IconButton>
            )}
            <IconButton
              title={t("Refresh eBPF diagnostics")}
              aria-label={t("Refresh eBPF diagnostics")}
              disabled={diagnostics.phase === "loading"}
              onClick={() => void api.ebpfDiagnostics.refresh()}
            >
              <Icon name="sync" />
            </IconButton>
          </div>
        }
      />

      {diagnostics.fetchedAt !== null && (
        <div className={styles.observedAt}>
          {t("Collected at {time}", {
            time: formatDateTime(diagnostics.fetchedAt, language),
          })}
        </div>
      )}
      {diagnostics.phase === "error" && data !== null && (
        <div className={styles.warning}>
          {t("Cached data; refresh failed: {error}", { error: diagnostics.error ?? "" })}
        </div>
      )}

      {data === null ? (
        diagnostics.phase === "error" ? (
          <EmptyState icon="developer_board">
            <span>
              {t("Unable to load eBPF diagnostics: {error}", {
                error: diagnostics.error ?? "",
              })}
            </span>
            <Button onClick={() => void api.ebpfDiagnostics.refresh()}>{t("Retry")}</Button>
          </EmptyState>
        ) : (
          <div className={styles.loading}>
            <Spinner />
          </div>
        )
      ) : data.inbounds.length === 0 ? (
        <EmptyState icon="developer_board">{t("No eBPF inbound is running")}</EmptyState>
      ) : (
        <div className="settings-stack">
          <Summary diagnostics={data} />
          {data.inbounds.map((inbound) => (
            <InboundSection
              key={inbound.tag}
              inbound={inbound}
              previous={previous.get(inbound.tag)}
            />
          ))}
          {data.kernelRuntime && <KernelRuntimeSection runtime={data.kernelRuntime} />}
        </div>
      )}
    </div>
  );
}

function Summary(props: { diagnostics: EBPFDiagnosticsResponse }) {
  const { t } = useI18n();
  const diagnostics = props.diagnostics;
  const worst = worstEBPFState(diagnostics.inbounds);
  const counts = new Map<string, number>();
  for (const inbound of diagnostics.inbounds) {
    counts.set(inbound.state, (counts.get(inbound.state) ?? 0) + 1);
  }
  const runtime = diagnostics.kernelRuntime;
  return (
    <div>
      <div className="list-section-title">{t("Overall status")}</div>
      <Card className={styles.summary}>
        <div className={styles.summaryHeadline}>
          {worst !== null && <StateDot tone={ebpfStateTone(worst)} />}
          <span>{t("{count} eBPF inbound", { count: diagnostics.inbounds.length })}</span>
        </div>
        <div className={styles.badges}>
          {[...counts.entries()].map(([state, count]) => (
            <Badge key={state} tone={ebpfStateTone(state)}>
              {stateLabel(state, t)} · {count}
            </Badge>
          ))}
        </div>
        {runtime && (
          <div className={styles.summaryMetrics}>
            <DataLine label={t("Kernel programs")} value={runtime.programs.length} />
            <DataLine
              label={t("Kernel maps")}
              value={runtime.mapOccupancy?.maps.length ?? 0}
            />
          </div>
        )}
      </Card>
    </div>
  );
}

function InboundSection(props: {
  inbound: EBPFInboundDiagnostics;
  previous?: EBPFInboundDiagnostics;
}) {
  const { t, language } = useI18n();
  const inbound = props.inbound;
  return (
    <div>
      <div className="list-section-title">{inbound.tag || "eBPF"}</div>
      <div className={styles.cardGrid}>
        <Card
          title={t("Data planes")}
          actions={
            <Badge tone={ebpfStateTone(inbound.state)}>
              <span className={styles.stateBadge}>
                <StateDot tone={ebpfStateTone(inbound.state)} />
                {stateLabel(inbound.state, t)}
              </span>
            </Badge>
          }
        >
          {inbound.schemaVersion > SUPPORTED_EBPF_SCHEMA_VERSION && (
            <div className={styles.warningInline}>
              {t("Newer diagnostics schema {version}; some fields may not be shown", {
                version: inbound.schemaVersion,
              })}
            </div>
          )}
          <DataLine
            label={t("Local data plane")}
            value={inbound.localEnabled ? inbound.localDataPlane : t("Disabled")}
            mono={inbound.localEnabled}
          />
          <DataLine
            label={t("Shared data plane")}
            value={inbound.sharedEnabled ? inbound.sharedDataPlane : t("Disabled")}
            mono={inbound.sharedEnabled}
          />
          <DataLine
            label={t("FakeIP ICMP reply")}
            value={inbound.fakeIPICMPReply ? t("Enabled") : t("Disabled")}
          />
        </Card>

        <Card title={t("Recovery and policy")}>
          <DataLine
            label={t("Recovery pending")}
            value={inbound.recoveryPending ? t("Enabled") : t("Disabled")}
          />
          <DataLine
            label={t("Unrecoverable")}
            value={inbound.recoveryUnrecoverable ? t("Enabled") : t("Disabled")}
          />
          <DataLine
            label={t("Rule-set policy")}
            value={
              inbound.bypassRuleSetPending
                ? t("Synchronizing")
                : inbound.bypassRuleSetConsistent
                  ? t("Consistent")
                  : t("Inconsistent")
            }
          />
          <DataLine
            label={t("Policy version")}
            value={formatCount(inbound.bypassRuleSetPolicyVersion, language)}
            mono
          />
          <DataLine
            label={t("Expected version")}
            value={formatCount(inbound.bypassRuleSetExpectedPolicyVersion, language)}
            mono
          />
          <DataLine
            label={t("Retry count")}
            value={formatCount(inbound.bypassRuleSetRetryCount, language)}
            mono
          />
          {Object.entries(inbound.bypassRuleSetBackendState).map(([name, state]) => (
            <DataLine
              key={name}
              label={name}
              value={state.known ? formatCount(state.version, language) : t("Unknown")}
              mono
            />
          ))}
          {inbound.lastError !== "" && (
            <DataLine label={t("Last error")} value={inbound.lastError} mono />
          )}
          <OptionalTime label={t("Last error time")} value={inbound.lastErrorAt} />
          <OptionalTime label={t("Last recovery")} value={inbound.lastRecoveryAt} />
          <OptionalTime label={t("Next retry")} value={inbound.nextRetryAt} />
        </Card>

        {inbound.attachments.length > 0 && (
          <Card title={t("Attachments")} wide>
            <div className={styles.itemList}>
              {inbound.attachments.map((attachment, index) => (
                <div
                  className={styles.item}
                  key={`${attachment.interfaceIndex}/${attachment.role}/${index}`}
                >
                  <div className={styles.itemTitle}>
                    <span className="mono">{attachment.interfaceName || "?"}</span>
                    <Badge>#{attachment.interfaceIndex}</Badge>
                  </div>
                  <div className={styles.itemDetails}>
                    <DataLine label={t("Role")} value={attachment.role || "-"} mono />
                    <DataLine label={t("Framing")} value={attachment.framing || "-"} mono />
                    <DataLine label={t("Mechanism")} value={attachment.mechanism || "-"} mono />
                    <DataLine
                      label={t("ICMP echo reply")}
                      value={attachment.icmpEchoReply ? t("Enabled") : t("Disabled")}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        <UDPRuntime inbound={inbound} previous={props.previous} />
        <CounterCard counters={inbound.counters} previous={props.previous?.counters} />
      </div>
    </div>
  );
}

function UDPRuntime(props: {
  inbound: EBPFInboundDiagnostics;
  previous?: EBPFInboundDiagnostics;
}) {
  const { t, language } = useI18n();
  const inbound = props.inbound;
  const reply = inbound.udpReplySockets;
  const nat = inbound.udpNAT;
  return (
    <Card title={t("UDP runtime")}>
      <DataLine label={t("Sessions")} value={formatCount(inbound.udpSessionCount, language)} mono />
      {reply && (
        <>
          <DataLine label={t("Reply sockets")} value={formatCount(reply.count, language)} mono />
          <DataLine label={t("Peak")} value={formatCount(reply.peak, language)} mono />
          <CounterLine
            label={t("Evicted")}
            value={reply.evicted}
            previous={props.previous?.udpReplySockets?.evicted}
          />
          <CounterLine
            label={t("Capacity rejected")}
            value={reply.capacityRejected}
            previous={props.previous?.udpReplySockets?.capacityRejected}
          />
        </>
      )}
      {nat && (
        <>
          <DataLine
            label={t("Active NAT sessions")}
            value={formatCount(nat.activeSessions, language)}
            mono
          />
          <DataLine
            label={t("Created sessions")}
            value={formatCount(nat.createdSessions, language)}
            mono
          />
          <CounterLine
            label={t("Queue drops")}
            value={nat.queueDrops}
            previous={props.previous?.udpNAT?.queueDrops}
          />
          <DataLine
            label={t("Socket release events")}
            value={formatCount(nat.socketReleaseEvents, language)}
            mono
          />
          <DataLine
            label={t("Socket release matched")}
            value={formatCount(nat.socketReleaseMatched, language)}
            mono
          />
          <CounterLine
            label={t("Pending release rejected")}
            value={nat.pendingReleaseCapacityRejected}
            previous={props.previous?.udpNAT?.pendingReleaseCapacityRejected}
          />
          <CounterLine
            label={t("Release notification drops")}
            value={nat.releaseNotificationDrops}
            previous={props.previous?.udpNAT?.releaseNotificationDrops}
          />
        </>
      )}
    </Card>
  );
}

function CounterCard(props: { counters?: EBPFCounters; previous?: EBPFCounters }) {
  const { t } = useI18n();
  const counters = props.counters;
  if (!counters) {
    return null;
  }
  const failures = FAILURE_COUNTERS.filter((key) => counters[key] > 0n);
  return (
    <Card title={t("Failure counters")}>
      {failures.length === 0 ? (
        <div className={styles.quiet}>{t("No failures recorded")}</div>
      ) : (
        failures.map((key) => (
          <CounterLine
            key={key}
            label={<code>{key}</code>}
            value={counters[key]}
            previous={props.previous?.[key]}
          />
        ))
      )}
      <details className={styles.counterDetails}>
        <summary>{t("Traffic and recovery counters")}</summary>
        <div className={styles.counterBody}>
          {ACTIVITY_COUNTERS.map((key) => (
            <CounterLine
              key={key}
              label={<code>{key}</code>}
              value={counters[key]}
              previous={props.previous?.[key]}
            />
          ))}
        </div>
      </details>
    </Card>
  );
}

function CounterLine(props: {
  label: ReactNode;
  value: bigint;
  previous?: bigint;
}) {
  const { language } = useI18n();
  const delta = positiveCounterDelta(props.value, props.previous);
  return (
    <DataLine
      label={props.label}
      value={
        <span className={styles.counterValue}>
          <span>{formatCount(props.value, language)}</span>
          {delta > 0n && <Badge tone="bad">+{formatCount(delta, language)}</Badge>}
        </span>
      }
      mono
    />
  );
}

function KernelRuntimeSection(props: { runtime: EBPFKernelRuntimeDiagnostics }) {
  const { t, language } = useI18n();
  const runtime = props.runtime;
  return (
    <div>
      <div className="list-section-title">{t("Kernel runtime")}</div>
      <Card>
        <details className={styles.kernelDetails}>
          <summary>
            {t("Kernel programs")} · {runtime.programs.length}
          </summary>
          <div className={styles.kernelBody}>
            {runtime.programsError !== "" && (
              <div className={styles.warningInline}>
                {t("Program enumeration failed: {error}", { error: runtime.programsError })}
              </div>
            )}
            <div className={styles.itemList}>
              {runtime.programs.map((program) => (
                <div className={styles.item} key={program.id}>
                  <div className={styles.itemTitle}>
                    <span className="mono">{program.name || `#${program.id}`}</span>
                    <Badge>{program.type}</Badge>
                  </div>
                  <DataLine label="ID" value={program.id} mono />
                  <DataLine label={t("Program maps")} value={program.mapCount} />
                  {program.mapIDs.length > 0 && (
                    <DataLine label="map IDs" value={program.mapIDs.join(", ")} mono />
                  )}
                </div>
              ))}
            </div>
            {runtime.mapOccupancy && (
              <>
                <div className={styles.subheading}>
                  {t("Map occupancy")}
                  <Badge>{runtime.mapOccupancy.status || t("Unknown")}</Badge>
                </div>
                {runtime.mapOccupancy.error !== "" && (
                  <div className={styles.warningInline}>{runtime.mapOccupancy.error}</div>
                )}
                <div className={styles.itemList}>
                  {runtime.mapOccupancy.maps.map((map) => (
                    <MapItem key={map.id} map={map} language={language} />
                  ))}
                </div>
              </>
            )}
          </div>
        </details>
      </Card>
    </div>
  );
}

function MapItem(props: { map: EBPFMapDiagnostics; language: string }) {
  const { t } = useI18n();
  const map = props.map;
  const percent = map.supported ? occupancyPercent(map.entries, map.maxEntries) : null;
  return (
    <div className={styles.item}>
      <div className={styles.itemTitle}>
        <span className="mono">{map.name || `#${map.id}`}</span>
        <Badge>{map.type}</Badge>
      </div>
      <DataLine label="ID" value={map.id} mono />
      <DataLine
        label={t("Entries")}
        value={
          map.supported
            ? `${map.entries.toLocaleString(props.language)} / ${map.maxEntries.toLocaleString(props.language)}`
            : t("Occupancy unavailable")
        }
        mono={map.supported}
      />
      {percent !== null && (
        <div className={styles.occupancy}>
          <div className={styles.occupancyBar} style={{ width: `${percent}%` }} />
          <span>{percent.toFixed(percent < 10 ? 1 : 0)}%</span>
        </div>
      )}
      {map.error !== "" && <div className={styles.warningInline}>{map.error}</div>}
    </div>
  );
}

function OptionalTime(props: { label: string; value?: bigint }) {
  const { language } = useI18n();
  const milliseconds = unixMillis(props.value);
  return milliseconds === null ? null : (
    <DataLine label={props.label} value={formatDateTime(milliseconds, language)} />
  );
}

function stateLabel(state: string, t: Translate): string {
  switch (state) {
    case "normal":
      return t("Normal");
    case "waiting_for_interface":
      return t("Waiting for interface");
    case "recovering":
      return t("Recovering");
    case "needs_attention":
      return t("Needs attention");
    default:
      return t("Unknown state: {state}", { state });
  }
}

function formatCount(value: bigint, language: string): string {
  return value.toLocaleString(language);
}
