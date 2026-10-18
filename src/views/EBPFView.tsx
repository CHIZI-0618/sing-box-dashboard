import { useEffect, useRef, useState, type ReactNode } from "react";

import {
  ebpfDiagnosticsJson,
  ebpfInboundHealth,
  ebpfMapHealth,
  ebpfTCDegradation,
  ebpfStateTone,
  occupancyPercent,
  positiveCounterDelta,
  unixMillis,
  worstEBPFState,
  type EBPFHealthKind as HealthKind,
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
  EBPFBypassRuleSetDiagnostics,
  EBPFDiagnosticsResponse,
  EBPFInboundDiagnostics,
  EBPFKernelRuntimeDiagnostics,
  EBPFMapDiagnostics,
} from "../gen/daemon/started_service_pb";
import { ToolsPageHeader } from "./ToolsView";
import styles from "./EBPFView.module.css";

type CounterKey = keyof Omit<EBPFCounters, "$typeName" | "$unknown">;

interface DiagnosticEvent {
  id: string;
  tag: string;
  at: number;
  kind: HealthKind;
  message: string;
}

const FAILURE_COUNTERS: CounterKey[] = [
  "assignmentLookupFailures",
  "tcSocketLookupFailures",
  "tcSKAssignFailures",
  "tcAssignmentUpdateFailures",
  "tcReturnUpdateFailures",
  "tcReturnConflicts",
  "tcReturnLookupFailures",
  "tokenReservationFailures",
  "rewriteFailures",
  "sharedReconcileFailures",
  "recoveryFailures",
  "fakeIPICMPRewriteFailureDrops",
];

const ACTIVITY_COUNTERS: CounterKey[] = [
  "tcLocalFragmentPasses",
  "tcSharedFragmentPasses",
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
  const [deep, setDeep] = useState(false);
  const diagnosticQuery = deep ? api.ebpfDeepDiagnostics : api.ebpfDiagnostics;
  const diagnostics = useQuery(diagnosticQuery);
  const previousInbounds = useRef(new Map<string, EBPFInboundDiagnostics>());
  const [events, setEvents] = useState<DiagnosticEvent[]>([]);

  useEffect(() => {
    void diagnosticQuery.refresh();
    return () => diagnosticQuery.invalidate();
  }, [diagnosticQuery]);

  const data = diagnostics.data;
  const previous = previousInbounds.current;
  useEffect(() => {
    if (diagnostics.phase === "loaded" && data !== null) {
      const additions: DiagnosticEvent[] = [];
      const observedAt = diagnostics.fetchedAt ?? Number(data.inbounds[0]?.observedAt ?? 0n);
      for (const inbound of data.inbounds) {
        const before = previousInbounds.current.get(inbound.tag);
        const currentHealth = ebpfInboundHealth(inbound);
        const previousHealth = before === undefined ? undefined : ebpfInboundHealth(before);
        if (before === undefined || previousHealth !== currentHealth) {
          additions.push({
            id: `${inbound.tag}/${observedAt}/${currentHealth}`,
            tag: inbound.tag,
            at: observedAt,
            kind: currentHealth,
            message: healthDescription(inbound, currentHealth),
          });
        }
      }
      if (additions.length > 0) {
        setEvents((current) => [...additions.reverse(), ...current].slice(0, 40));
      }
      previousInbounds.current = new Map(data.inbounds.map((inbound) => [inbound.tag, inbound]));
    }
  }, [data, diagnostics.fetchedAt, diagnostics.phase]);

  return (
    <div className="page">
      <ToolsPageHeader
        title={t("eBPF Diagnostics")}
        actions={
          <div className={styles.headerActions}>
            <Button onClick={() => setDeep((value) => !value)}>
              {deep ? t("Lightweight status") : t("Inspect owned maps")}
            </Button>
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
              onClick={() => void diagnosticQuery.refresh()}
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
            <Button onClick={() => void diagnosticQuery.refresh()}>{t("Retry")}</Button>
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
          <RecentEvents events={events} />
          {data.inbounds.map((inbound) => (
            <InboundSection
              key={inbound.tag}
              inbound={inbound}
              previous={previous.get(inbound.tag)}
              events={events.filter((event) => event.tag === inbound.tag)}
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
  const mapHealth = ebpfMapHealth(runtime);
  const attention = diagnostics.inbounds.filter(
    (inbound) => inbound.state === "needs_attention" || inbound.recoveryUnrecoverable,
  ).length;
  const pending = diagnostics.inbounds.filter(
    (inbound) => inbound.recoveryPending || inbound.nextRetryAt !== undefined,
  ).length;
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
            <DataLine
              label={t("Attention")}
              value={<Badge tone={attention > 0 ? "bad" : "good"}>{attention}</Badge>}
            />
            <DataLine
              label={t("Pending retries")}
              value={<Badge tone={pending > 0 ? "medium" : "good"}>{pending}</Badge>}
            />
            <DataLine
              label={t("Map health")}
              value={
                <Badge
                  tone={
                    mapHealth.total === 0 || mapHealth.high > 0 || mapHealth.unavailable > 0
                      ? "medium"
                      : "good"
                  }
                >
                  {mapHealth.total === 0
                    ? t("Unknown")
                    : mapHealth.high > 0 || mapHealth.unavailable > 0
                      ? t("Needs attention")
                      : t("Normal")}
                </Badge>
              }
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
  events: DiagnosticEvent[];
}) {
  const { t, language } = useI18n();
  const inbound = props.inbound;
  const showNotice = inbound.state !== "normal" || inbound.lastError !== "";
  return (
    <div>
      <div className="list-section-title">{inbound.tag || "eBPF"}</div>
      {showNotice && (
        <div className={styles.runtimeNotice}>
          <div className={styles.noticeHeadline}>
            <StateDot tone={ebpfStateTone(inbound.state)} />
            <strong>{stateLabel(inbound.state, t)}</strong>
            {inbound.recoveryUnrecoverable && <Badge tone="bad">{t("Rebuild required")}</Badge>}
            {inbound.recoveryPending && <Badge tone="medium">{t("Recovery pending")}</Badge>}
          </div>
          {inbound.lastError !== "" && <div className={styles.noticeError}>{inbound.lastError}</div>}
          {inbound.nextRetryAt !== undefined && (
            <OptionalTime label={t("Next retry")} value={inbound.nextRetryAt} />
          )}
        </div>
      )}
      {inbound.kernelRuntime && <KernelRuntimeSection runtime={inbound.kernelRuntime} />}
      <HealthCard inbound={inbound} events={props.events} />
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
            label={t("Effective paths")}
            value={<PathBadges inbound={inbound} />}
          />
          {inbound.waitingRoles.length > 0 && (
            <DataLine
              label={t("Waiting paths")}
              value={inbound.waitingRoles.join(", ")}
              mono
            />
          )}
          {inbound.waitingInterfaces.length > 0 && (
            <DataLine
              label={t("Waiting interfaces")}
              value={inbound.waitingInterfaces.join(", ")}
              mono
            />
          )}
          {inbound.policyEpoch && (
            <>
              <DataLine
                label={t("Policy epoch")}
                value={`local ${formatCount(inbound.policyEpoch.localConfirmed, language)}/${formatCount(inbound.policyEpoch.localExpected, language)} · shared ${formatCount(inbound.policyEpoch.sharedConfirmed, language)}/${formatCount(inbound.policyEpoch.sharedExpected, language)}`}
                mono
              />
              <DataLine
                label={t("Policy convergence")}
                value={
                  <Badge tone={inbound.policyEpoch.converged ? "good" : "medium"}>
                    {inbound.policyEpoch.converged ? t("Converged") : t("Pending")}
                  </Badge>
                }
              />
            </>
          )}
          <DataLine
            label={t("FakeIP ICMP reply")}
            value={inbound.fakeIPICMPReply ? t("Enabled") : t("Disabled")}
          />
          {inbound.localSelfBypassMode !== "" && (
            <>
              <DataLine
                label={t("Self-bypass")}
                value={inbound.localSelfBypassMode}
                mono
              />
              <DataLine
                label={t("Self-bypass cleanup")}
                value={inbound.localSelfBypassCleanupMode || "-"}
                mono
              />
            </>
          )}
          {inbound.localCgroupAttachMode !== "" && (
            <>
              <DataLine
                label={t("Cgroup attach")}
                value={inbound.localCgroupAttachMode}
                mono
              />
              <DataLine
                label={t("UDP cleanup")}
                value={inbound.localUdpCleanupMode || "-"}
                mono
              />
              <DataLine
                label={t("Userspace cleanup")}
                value={inbound.localUdpUserspaceCleanupMode || "-"}
                mono
              />
              <DataLine
                label={t("Socket storage")}
                value={inbound.localUdpStorageMode || "-"}
                mono
              />
              <DataLine
                label={t("Time source")}
                value={inbound.localUdpTimeMode || "-"}
                mono
              />
              <DataLine label={t("UDP state")} value={inbound.localUdpState || "-"} mono />
              <DataLine
                label={t("UDP map pressure")}
                value={inbound.localUdpMapPressure || t("Unknown")}
                mono
              />
              <DataLine
                label={t("UDP recovery")}
                value={inbound.localUdpRecoveryMode || "-"}
                mono
              />
              <DataLine
                label={t("UDP generation")}
                value={formatCount(BigInt(inbound.localUdpNetworkGeneration), language)}
                mono
              />
              <DataLine
                label={t("Release observer")}
                value={inbound.localUdpReleaseObserver ? t("Enabled") : t("Disabled")}
                mono
              />
              <DataLine
                label={t("Release program")}
                value={inbound.localUdpReleaseProgram || "-"}
                mono
              />
              {inbound.localUdpReleaseFallbackReason !== "" && (
                <DataLine
                  label={t("Release fallback")}
                  value={inbound.localUdpReleaseFallbackReason}
                  mono
                />
              )}
            </>
          )}
        </Card>

        {inbound.tcBackendMode !== "" && (
          <Card title={t("TC runtime")}>
            <DataLine label={t("Backend")} value={inbound.tcBackendMode} mono />
            <DataLine label={t("Listener lookup")} value={inbound.tcListenerLookupMode || "-"} mono />
            <DataLine label={t("Attachment mechanism")} value={inbound.tcAttachmentMode || "-"} mono />
            <DataLine
              label={t("Delivery interface")}
              value={
                inbound.tcDeliveryInterface === ""
                  ? "-"
                  : `${inbound.tcDeliveryInterface} (#${inbound.tcDeliveryInterfaceIndex})`
              }
              mono
            />
            <DataLine
              label={t("Policy routing")}
              value={`mark=${inbound.tcRoutingMark} table=${inbound.tcRoutingTable} priority=${inbound.tcRoutingPriority} slot=${inbound.tcRoutingSlot}`}
              mono
            />
            <DataLine
              label={t("Attachments")}
              value={`${inbound.tcAttachmentCount} · ${t("retired {attachments} / {deliveries}", {
                attachments: inbound.tcRetiredAttachmentCount,
                deliveries: inbound.tcRetiredDeliveryCount,
              })}`}
              mono
            />
            <DataLine
              label={t("Health")}
              value={inbound.tcHealthStatus || "-"}
              mono
            />
            <TCDegradation inbound={inbound} previous={props.previous} />
            <DataLine
              label={t("Network generation")}
              value={formatCount(inbound.tcNetworkGeneration, language)}
              mono
            />
            <DataLine
              label={t("Assignment map")}
              value={inbound.tcAssignmentSweepUsageKnown ? `${formatCount(inbound.tcAssignmentSweepEntries, language)} / ${formatCount(inbound.tcAssignmentSweepCapacity, language)}` : t("Unknown")}
              mono
            />
            <DataLine label={t("Network namespace")} value={inbound.tcNetworkNamespace || "-"} mono />
            <DataLine
              label={t("Return route map")}
              value={inbound.tcReturnSweepUsageKnown ? `${formatCount(inbound.tcReturnSweepEntries, language)} / ${formatCount(inbound.tcReturnSweepCapacity, language)}` : t("Unknown")}
              mono
            />
            <DataLine
              label={t("Assignment pressure")}
              value={inbound.tcAssignmentSweepPressure ? t("Active") : t("Normal")}
              mono
            />
            <DataLine
              label={t("Assignment sweeps")}
              value={`${formatCount(inbound.tcAssignmentSweepRuns, language)} · ${formatCount(inbound.tcAssignmentSweepPartial, language)} ${t("partial")}`}
              mono
            />
            {inbound.tcAssignmentSweepFailure && (
              <DataLine
                label={t("Assignment sweep failure")}
                value={`${inbound.tcAssignmentSweepFailureMap}: ${inbound.tcAssignmentSweepFailure}`}
                mono
              />
            )}
            <DataLine
              label={t("Recovery queue overflows")}
              value={formatCount(inbound.cgroupRecoveryQueueOverflows, language)}
              mono
            />
            <OptionalTime label={t("Last health check")} value={inbound.tcLastHealthCheckAt} />
            <OptionalTime label={t("Last reconcile")} value={inbound.tcLastReconcileAt} />
            {inbound.tcRequiresRebuild && (
              <Badge tone="bad">{t("Rebuild required")}</Badge>
            )}
          </Card>
        )}

        <Card title={t("Recovery and policy")}>
          <DataLine
            label={t("Recovery pending")}
            value={inbound.recoveryPending ? t("Enabled") : t("Disabled")}
          />
          <DataLine
            label={t("Unrecoverable")}
            value={inbound.recoveryUnrecoverable ? t("Enabled") : t("Disabled")}
          />
          {inbound.localEnabled && inbound.localBypassRuleSet && (
            <RuleSetPolicy
              label={t("Local rule-set policy")}
              policy={inbound.localBypassRuleSet}
            />
          )}
          {inbound.sharedEnabled && inbound.sharedBypassRuleSet && (
            <RuleSetPolicy
              label={t("Shared rule-set policy")}
              policy={inbound.sharedBypassRuleSet}
            />
          )}
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
                    <DataLine label={t("Instance slot")} value={attachment.slot} mono />
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
        <DataPlaneCounterCard inbound={inbound} previous={props.previous} />
        <CounterCard counters={inbound.counters} previous={props.previous?.counters} />
      </div>
    </div>
  );
}

function healthDescription(inbound: EBPFInboundDiagnostics, kind: HealthKind): string {
  switch (kind) {
    case "healthy":
      return "All configured data planes report healthy and the collected maps are below their pressure thresholds.";
    case "unverified":
      return "Data planes report healthy, but map occupancy was not collected or could not be verified. This is not evidence that an earlier map pressure cleared.";
    case "degraded":
      return inbound.localUdpState === "timeout_fallback"
        ? "Socket release is unavailable; connected UDP uses reverse-index and timeout fallback."
        : "A configured data plane is operating on a fallback path.";
    case "recovering":
      return "A data-plane recovery attempt is pending.";
    case "policy_pending":
      return "The latest policy epoch has not converged on every backend.";
    case "attachment_lost":
      return "A TC attachment was lost or requires an inbound rebuild.";
    case "map_pressure":
      return "At least one eBPF map is above its pressure threshold.";
    case "udp_recovery_failed":
      return "Connected UDP recovery is degraded and may lose original destinations.";
  }
}

function healthLabel(kind: HealthKind, t: Translate): string {
  switch (kind) {
    case "healthy": return t("Healthy");
    case "unverified": return t("Map health unverified");
    case "degraded": return t("Degraded");
    case "recovering": return t("Recovering");
    case "policy_pending": return t("Policy pending");
    case "attachment_lost": return t("Attachment lost");
    case "map_pressure": return t("Map pressure");
    case "udp_recovery_failed": return t("UDP recovery failed");
  }
}

function healthTone(kind: HealthKind): "good" | "medium" | "bad" | "neutral" {
  switch (kind) {
    case "healthy": return "good";
    case "unverified": return "neutral";
    case "recovering":
    case "policy_pending":
    case "degraded": return "medium";
    case "attachment_lost":
    case "map_pressure":
    case "udp_recovery_failed": return "bad";
  }
}

function HealthCard(props: {
  inbound: EBPFInboundDiagnostics;
  events: DiagnosticEvent[];
}) {
  const { t, language } = useI18n();
  const kind = ebpfInboundHealth(props.inbound);
  const matching = props.events.filter((event) => event.kind === kind);
  const first = matching.at(-1)?.at;
  const last = matching[0]?.at;
  const action = kind === "unverified"
    ? t("Inspect owned maps")
    : kind === "healthy" || kind === "degraded"
    ? t("No immediate action required")
    : kind === "policy_pending" || kind === "recovering"
      ? t("Wait for the next reconcile")
      : t("Refresh diagnostics and restart the inbound if the condition persists");
  return (
    <Card className={styles.healthCard}>
      <div className={styles.healthHeadline}>
        <StateDot tone={healthTone(kind)} />
        <strong>{healthLabel(kind, t)}</strong>
        <Badge tone={healthTone(kind)}>{props.inbound.tag || "eBPF"}</Badge>
      </div>
      <div className={styles.healthDescription}>{healthDescription(props.inbound, kind)}</div>
      <div className={styles.healthTimes}>
        <DataLine
          label={t("First observed")}
          value={first === undefined ? "-" : formatDateTime(first, language)}
        />
        <DataLine
          label={t("Last observed")}
          value={last === undefined ? "-" : formatDateTime(last, language)}
        />
        <DataLine label={t("Recommended action")} value={action} />
      </div>
    </Card>
  );
}

function RecentEvents(props: { events: DiagnosticEvent[] }) {
  const { t, language } = useI18n();
  return (
    <div>
      <div className="list-section-title">{t("Recent eBPF events")}</div>
      <Card>
        <div className={styles.timelineHint}>{t("Events observed since this page was opened")}</div>
        {props.events.length === 0 ? (
          <div className={styles.quiet}>{t("No state changes observed")}</div>
        ) : (
          <div className={styles.timeline}>
            {props.events.map((event) => (
              <div className={styles.timelineItem} key={event.id}>
                <StateDot tone={healthTone(event.kind)} />
                <time>{formatDateTime(event.at, language)}</time>
                <strong>{event.tag || "eBPF"}</strong>
                <span>{healthLabel(event.kind, t)}</span>
                <small>{event.message}</small>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function DataPlaneCounterCard(props: {
  inbound: EBPFInboundDiagnostics;
  previous?: EBPFInboundDiagnostics;
}) {
  const { t, language } = useI18n();
  const counters = props.inbound.counters;
  if (!counters) return null;
  const sharedRewrite = counters.sharedIngressFragmentPasses + counters.sharedEgressFragmentPasses;
  const previousShared = props.previous?.counters
    ? props.previous.counters.sharedIngressFragmentPasses + props.previous.counters.sharedEgressFragmentPasses
    : undefined;
  const recovery = counters.recoveryAttempts + counters.recoverySuccesses + counters.recoveryFailures;
  const fakeIP = counters.fakeIPICMPReplies + counters.fakeIPICMPPassThrough;
  return (
    <Card title={t("Data-plane counters")}>
      <CounterLine label={t("Local TC fragment passes")} value={counters.tcLocalFragmentPasses} previous={props.previous?.counters?.tcLocalFragmentPasses} />
      <CounterLine label={t("Shared socket-assignment fragment passes")} value={counters.tcSharedFragmentPasses} previous={props.previous?.counters?.tcSharedFragmentPasses} />
      <CounterLine label={t("Shared packet-rewrite fragment passes")} value={sharedRewrite} previous={previousShared} />
      <DataLine label={t("UDP active sessions")} value={formatCount(BigInt(props.inbound.udpNAT?.activeSessions ?? 0), language)} mono />
      <DataLine label={t("Recovery activity")} value={formatCount(recovery, language)} mono />
      <DataLine label={t("FakeIP ICMP activity")} value={formatCount(fakeIP, language)} mono />
      <div className={styles.timelineHint}>{t("Only counters exported by the active backend are shown")}</div>
    </Card>
  );
}

function TCDegradation(props: { inbound: EBPFInboundDiagnostics; previous?: EBPFInboundDiagnostics }) {
  const { t, language } = useI18n();
  const degradation = ebpfTCDegradation(props.inbound, props.previous);
  return (
    <DataLine
      label={t("TC degradation")}
      value={
        <span className={styles.counterValue}>
          <Badge tone={degradation.active ? "medium" : "good"}>
            {degradation.active ? t("Attention") : t("Normal")}
          </Badge>
          <span>{formatCount(degradation.failures, language)}</span>
          {degradation.recentFailures > 0n && (
            <Badge tone="bad">+{formatCount(degradation.recentFailures, language)}</Badge>
          )}
        </span>
      }
      mono
    />
  );
}

function RuleSetPolicy(props: { label: string; policy: EBPFBypassRuleSetDiagnostics }) {
  const { t, language } = useI18n();
  const policy = props.policy;
  return (
    <div className={styles.policy}>
      <div className={styles.policyHeading}>{props.label}</div>
      <DataLine
        label={t("Status")}
        value={
          policy.pending
            ? t("Synchronizing")
            : policy.consistent
              ? t("Consistent")
              : t("Inconsistent")
        }
      />
      <DataLine
        label={t("Policy version")}
        value={formatCount(policy.policyVersion, language)}
        mono
      />
      <DataLine
        label={t("Expected version")}
        value={formatCount(policy.expectedPolicyVersion, language)}
        mono
      />
      <DataLine
        label={t("Retry count")}
        value={formatCount(policy.retryCount, language)}
        mono
      />
      {Object.entries(policy.backendState).map(([name, state]) => (
        <DataLine
          key={name}
          label={name}
          value={state.known ? formatCount(state.version, language) : t("Unknown")}
          mono
        />
      ))}
    </div>
  );
}

function PathBadges(props: { inbound: EBPFInboundDiagnostics }) {
  const { inbound } = props;
  const paths: string[] = [];
  if (inbound.localEnabled) {
    const detail = inbound.localDataPlane === "cgroup"
      ? inbound.localCgroupAttachMode
      : inbound.tcAttachmentMode;
    paths.push(`local:${inbound.localDataPlane || "?"}${detail ? `/${detail}` : ""}`);
  }
  if (inbound.sharedEnabled) {
    const detail = inbound.sharedDataPlane === "socket_assign" || inbound.sharedDataPlane === "packet_rewrite"
      ? inbound.tcAttachmentMode
      : "";
    paths.push(`shared:${inbound.sharedDataPlane || "?"}${detail ? `/${detail}` : ""}`);
  }
  return (
    <span className={styles.pathBadges}>
      {paths.length === 0 ? "-" : paths.map((path) => <Badge key={path}>{path}</Badge>)}
    </span>
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
  const mapHealth = ebpfMapHealth(runtime);
  return (
    <div>
      <div className="list-section-title">{t("Kernel runtime")}</div>
      <Card>
        <details className={styles.kernelDetails}>
          <summary>
            {t("Kernel programs")} · {runtime.programs.length}
            {runtime.mapOccupancy && (
              <Badge tone={runtime.mapOccupancy.status === "degraded" ? "bad" : runtime.mapOccupancy.status === "warning" ? "medium" : "good"}>
                {mapHealth.total === 0 ? t("Unknown") : `${mapHealth.supported}/${mapHealth.total}`}
              </Badge>
            )}
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
  const occupancyRecoveryFailed = map.pressure === "recovery_failed";
  const occupancyNotApplicable = map.pressure === "not_applicable";
  const occupancyConfigured =
    map.category === "configured_policy" && map.supported && !occupancyRecoveryFailed && !occupancyNotApplicable;
  const percent = map.supported && !occupancyConfigured ? occupancyPercent(map.entries, map.maxEntries) : null;
  return (
    <div className={styles.item}>
      <div className={styles.itemTitle}>
        <span className="mono">{map.name || `#${map.id}`}</span>
        <span className={styles.badges}>
          <Badge>{map.type}</Badge>
          {map.pressure !== "" && (
            <Badge
              tone={
                map.pressure === "healthy"
                  ? "good"
                  : map.pressure === "warning"
                    ? "medium"
                      : map.pressure === "not_applicable" || occupancyConfigured
                      ? undefined
                      : "bad"
              }
            >
              {occupancyConfigured ? t("Configured") : occupancyNotApplicable ? t("Not applicable") : map.pressure}
            </Badge>
          )}
        </span>
      </div>
      <DataLine label="ID" value={map.id} mono />
      <DataLine
        label={t("Entries")}
        value={
          map.supported
            ? `${map.entries.toLocaleString(props.language)} / ${map.maxEntries.toLocaleString(props.language)}`
            : occupancyNotApplicable
              ? t("Not applicable")
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
      {map.error !== "" && !occupancyNotApplicable && (
        <div className={styles.warningInline}>{map.error}</div>
      )}
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
