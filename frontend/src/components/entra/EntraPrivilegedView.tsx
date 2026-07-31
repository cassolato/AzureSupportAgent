import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api";
import { formatError } from "../../utils/format";
import { useDebounced } from "../../utils/perf";
import { PimReviewPanel } from "../PimReviewView";
import { EntraActivationsView } from "./EntraActivationsView";
import { Bar, EntraEmpty, SevBadge, useInitialSubTab } from "./EntraShared";

/**
 * Privileged Access Mission Control.
 *
 * One cockpit for every form of privilege, including the join no Microsoft surface shows:
 * a principal holding directory power AND Azure control-plane power at the same time.
 */

// The three PIM tabs are deliberately distinct and ordered settings -> events -> drift:
//   "pim"         the policy: what activation *should* require (approval, MFA, max duration)
//   "activations" the events: who actually elevated, when, and what they did with it
//   "jit-hygiene" the drift: privilege that was meant to be Just-In-Time and quietly went
//                 permanent, plus eligible roles nobody ever activates (the former
//                 /identity/pim screen)
type Tab = "overview" | "assignments" | "pim" | "activations" | "jit-hygiene" | "cross-plane";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "assignments", label: "Assignments" },
  { id: "pim", label: "PIM config" },
  { id: "activations", label: "Activations" },
  { id: "jit-hygiene", label: "JIT hygiene" },
  { id: "cross-plane", label: "Cross-plane" },
];

export function EntraPrivilegedView({
  connectionId,
  onOpenSetup,
}: {
  connectionId: string | null;
  onOpenSetup: () => void;
}) {
  const [tab, setTab] = useState<Tab>(useInitialSubTab(TABS.map((t) => t.id), "overview"));
  return (
    // h-full, not flex-1: the parent is EntraView's plain scroll box, not a flex column, so
    // flex-1 resolves to nothing there and this root would grow to its full content height.
    // h-full resolves against that box's definite height and bounds the tabs below it.
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-1 border-b bg-white px-4">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-2 text-[13px] font-medium ${
              tab === t.id ? "border-b-2 border-brand text-brand" : "text-gray-500 hover:text-gray-700"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>
      {/* The native tabs are plain documents that scroll as one block. The re-parented panel
          pins its own header and scrolls only its body, so it needs a *bounded* box — given a
          scrolling one it grows to full content height and its header scrolls away. So the
          container clips and each tab opts into the scrolling it actually wants. */}
      <div className="min-h-0 flex-1 overflow-hidden">
        {tab === "jit-hygiene" ? (
          <div className="flex h-full min-h-0 flex-col">
            <PimReviewPanel connectionId={connectionId} />
          </div>
        ) : (
          <div className="h-full overflow-auto">
            {tab === "overview" && <Overview connectionId={connectionId} onOpenSetup={onOpenSetup} />}
            {tab === "assignments" && <Assignments connectionId={connectionId} />}
            {tab === "pim" && <PimConfig connectionId={connectionId} onOpenSetup={onOpenSetup} />}
            {tab === "activations" && <EntraActivationsView connectionId={connectionId} />}
            {tab === "cross-plane" && <CrossPlane connectionId={connectionId} />}
          </div>
        )}
      </div>
    </div>
  );
}

function Kpi({ label, value, tone, note }: { label: string; value: number | string; tone?: string; note?: string }) {
  return (
    <div className="rounded-lg border bg-white p-3">
      <div className="text-[11px] uppercase tracking-wide text-gray-400">{label}</div>
      <div className={`text-xl font-semibold ${tone ?? "text-gray-900"}`}>{value}</div>
      {note && <div className="mt-0.5 text-[11px] text-gray-500">{note}</div>}
    </div>
  );
}

function Overview({ connectionId, onOpenSetup }: { connectionId: string | null; onOpenSetup: () => void }) {
  const q = useQuery({
    queryKey: ["entra-priv-overview", connectionId],
    queryFn: () => api.entraPrivilegedOverview(connectionId),
  });
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Loading…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;
  const c = d.counts;

  return (
    <div className="space-y-4 p-4">
      <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
        <Kpi label="Global admins" value={c.global_admins ?? 0}
             tone={(c.global_admins ?? 0) > 5 || (c.global_admins ?? 0) < 2 ? "text-red-600" : undefined} />
        <Kpi label="Privileged principals" value={c.privileged_principals ?? 0} />
        <Kpi label="Standing privileged" value={c.standing_privileged ?? 0}
             tone={(c.standing_privileged ?? 0) > 0 ? "text-amber-600" : undefined} />
        <Kpi label="Eligible" value={c.eligible ?? 0} />
        <Kpi label="PIM fully configured" value={`${c.pim_fully_configured ?? 0}/${c.pim_policies ?? 0}`}
             tone={(c.pim_policies ?? 0) > 0 && (c.pim_fully_configured ?? 0) < (c.pim_policies ?? 0)
               ? "text-amber-600" : undefined} />
        <Kpi label="Cross-plane" value={c.cross_plane ?? 0}
             tone={(c.cross_plane ?? 0) > 0 ? "text-red-600" : undefined} />
      </div>

      {!d.azure_link.available && (
        <div className="rounded-lg border border-sky-200 bg-sky-50 px-3 py-2 text-[13px] text-sky-900">
          <span className="font-medium">Cross-plane analysis unavailable.</span> {d.azure_link.reason}
        </div>
      )}
      {d.azure_link.available && d.azure_link.stale && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[13px] text-amber-900">
          The Azure RBAC cache ({d.azure_link.generated_at?.slice(0, 16) || "unknown"}) is older than this
          Entra snapshot. The cross-plane join is shown, but treat it as indicative rather than current.
        </div>
      )}

      <div className="rounded-lg border bg-white">
        <div className="border-b px-4 py-2 text-[13px] font-semibold text-gray-800">
          Privileged access findings
        </div>
        {d.findings.length === 0 ? (
          <EntraEmpty kind="clean" detail="No privileged-access findings." onOpenSetup={onOpenSetup} />
        ) : (
          <div className="divide-y">
            {d.findings.slice(0, 60).map((f) => (
              <div key={f.fingerprint} className="flex items-start gap-3 px-4 py-2">
                <SevBadge sev={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] text-gray-900">{f.title}</div>
                  <div className="text-xs text-gray-500">{f.signal_id}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Assignments({ connectionId }: { connectionId: string | null }) {
  const [kind, setKind] = useState<"standing" | "eligible" | "all">("standing");
  const [search, setSearch] = useState("");
  const dSearch = useDebounced(search, 150);
  const q = useQuery({
    queryKey: ["entra-priv-assignments", connectionId, kind, dSearch],
    queryFn: () => api.entraPrivilegedAssignments({ kind, search: dSearch || undefined }, connectionId),
  });
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Loading…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;

  return (
    <div className="p-4">
      <div className="mb-3 flex items-center gap-2">
        {(["standing", "eligible", "all"] as const).map((k) => (
          <button
            key={k}
            onClick={() => setKind(k)}
            className={`rounded px-2 py-1 text-xs font-medium ${
              kind === k ? "bg-gray-800 text-white" : "border text-gray-600"
            }`}
          >
            {k}
          </button>
        ))}
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by principal or role…"
          className="ml-auto w-72 rounded border px-2 py-1 text-sm"
        />
      </div>
      {!d.capabilities?.permanence_known && (
        <div className="mb-3 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          PIM schedule data was unavailable, so an active assignment cannot be distinguished from a
          live activation. Permanence is reported as unknown rather than assumed.
        </div>
      )}
      <div className="overflow-hidden rounded-lg border bg-white">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b bg-gray-50 text-left text-xs text-gray-500">
              <th className="px-3 py-2 font-medium">Principal</th>
              <th className="px-2 py-2 font-medium">Type</th>
              <th className="px-2 py-2 font-medium">Role</th>
              <th className="px-2 py-2 font-medium">Tier</th>
              <th className="px-2 py-2 font-medium">Kind</th>
              <th className="px-2 py-2 font-medium">Permanent</th>
              <th className="px-2 py-2 font-medium">Last activation</th>
            </tr>
          </thead>
          <tbody>
            {d.assignments.map((a, i) => (
              <tr key={`${a.id}-${i}`} className="border-b last:border-b-0">
                <td className="px-3 py-1.5 text-gray-900">
                  {a.principal_name || a.principal_upn || a.principal_id}
                  {a.source === "group" && (
                    <span className="ml-1 text-xs text-gray-400">via {a.source_group_name}</span>
                  )}
                </td>
                <td className="px-2 py-1.5 text-gray-600">{a.principal_type}</td>
                <td className="px-2 py-1.5 text-gray-800">{a.role_name}</td>
                <td className="px-2 py-1.5">
                  {a.role_tier === "tier0" ? (
                    <span className="rounded bg-red-100 px-1.5 py-0.5 text-[11px] text-red-700">tier 0</span>
                  ) : a.role_tier === "tier1" ? (
                    <span className="rounded bg-orange-100 px-1.5 py-0.5 text-[11px] text-orange-700">tier 1</span>
                  ) : (
                    <span className="text-xs text-gray-400">tier 2</span>
                  )}
                </td>
                <td className="px-2 py-1.5 text-gray-600">{a.assignment_kind}</td>
                <td className="px-2 py-1.5 text-gray-600">
                  {a.permanent === true ? "yes" : a.permanent === false ? "time-bound" : "unknown"}
                </td>
                <td className="px-2 py-1.5 text-gray-500">{a.last_activation?.slice(0, 10) || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-2 text-xs text-gray-400">
        Showing {d.assignments.length} of {d.total}.
      </div>
    </div>
  );
}

function PimConfig({ connectionId, onOpenSetup }: { connectionId: string | null; onOpenSetup: () => void }) {
  const q = useQuery({
    queryKey: ["entra-priv-pim", connectionId],
    queryFn: () => api.entraPrivilegedPimPolicies(connectionId),
  });
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Loading…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;
  if (!d.policies.length) {
    const domain = d.domain;
    return (
      <EntraEmpty
        kind={domain?.status === "unlicensed" ? "unlicensed" : domain?.status === "blind" ? "blind" : "clean"}
        detail={
          domain?.error ||
          "No PIM role management policies were collected. This grid is the only place approval, " +
            "MFA-on-activation, justification and duration settings appear together."
        }
        onOpenSetup={onOpenSetup}
      />
    );
  }

  const cell = (ok: boolean) =>
    ok ? (
      <span className="text-green-600">✓</span>
    ) : (
      <span className="font-semibold text-red-600">✕</span>
    );

  return (
    <div className="p-4">
      <div className="mb-2 text-xs text-gray-500">
        Worst-configured privileged roles first. Every column is an activation control — what a
        user must do to turn the role on.
      </div>
      <div className="overflow-hidden rounded-lg border bg-white">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b bg-gray-50 text-left text-xs text-gray-500">
              <th className="px-3 py-2 font-medium">Role</th>
              <th className="px-2 py-2 font-medium">Score</th>
              {d.controls.map((c) => (
                <th key={c.key} className="px-2 py-2 text-center font-medium">{c.label}</th>
              ))}
              <th className="px-2 py-2 font-medium">Max duration</th>
            </tr>
          </thead>
          <tbody>
            {d.policies.map((p) => (
              <tr key={p.role_id} className="border-b last:border-b-0">
                <td className="px-3 py-1.5">
                  <span className="text-gray-900">{p.role_name}</span>
                  {p.role_tier === "tier0" && (
                    <span className="ml-1 rounded bg-red-100 px-1 py-0.5 text-[10px] text-red-700">tier 0</span>
                  )}
                </td>
                <td className="w-24 px-2 py-1.5">
                  <div className="flex items-center gap-1">
                    <Bar value={p.score} tone={p.score === 100 ? "bg-green-500" : p.score >= 60 ? "bg-amber-500" : "bg-red-500"} />
                    <span className="w-8 text-right text-xs text-gray-600">{p.score}</span>
                  </div>
                </td>
                <td className="px-2 py-1.5 text-center">{cell(p.mfa_on_activation || p.auth_context_required)}</td>
                <td className="px-2 py-1.5 text-center">{cell(p.approval_required)}</td>
                <td className="px-2 py-1.5 text-center">{cell(p.justification_required)}</td>
                <td className="px-2 py-1.5 text-center">{cell(p.ticket_required)}</td>
                <td className="px-2 py-1.5 text-center">
                  {cell(p.max_activation_hours != null && p.max_activation_hours <= 8)}
                </td>
                <td className="px-2 py-1.5 text-center">{cell(p.notification_recipients > 0)}</td>
                <td className="px-2 py-1.5 text-gray-600">
                  {p.max_activation_hours != null ? `${p.max_activation_hours}h` : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


function CrossPlane({ connectionId }: { connectionId: string | null }) {
  const q = useQuery({
    queryKey: ["entra-priv-crossplane", connectionId],
    queryFn: () => api.entraPrivilegedCrossPlane(connectionId),
  });
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Loading…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;

  return (
    <div className="space-y-3 p-4">
      <div className="rounded-lg border bg-white p-3 text-[13px] text-gray-700">
        <span className="font-medium">Entra power beside Azure power.</span> A principal holding both is
        a single point of total compromise — and this correlation does not exist in any Microsoft surface.
      </div>
      {!d.azure_link.available ? (
        <EntraEmpty kind="blind" detail={d.azure_link.reason || "No Azure RBAC scan is available."} />
      ) : (
        <>
          {d.azure_link.stale && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
              Azure RBAC data is from {d.azure_link.generated_at?.slice(0, 16).replace("T", " ")}, older than
              this Entra snapshot. Re-run the RBAC scan for a current join.
            </div>
          )}
          <div className="overflow-hidden rounded-lg border bg-white">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b bg-gray-50 text-left text-xs text-gray-500">
                  <th className="px-3 py-2 font-medium">Principal</th>
                  <th className="px-2 py-2 font-medium">Entra power</th>
                  <th className="px-2 py-2 font-medium">Azure power</th>
                  <th className="px-2 py-2 font-medium">Scope</th>
                </tr>
              </thead>
              <tbody>
                {d.rows.map((r) => (
                  <tr key={r.principal_id} className={`border-b last:border-b-0 ${r.both_planes ? "bg-red-50/40" : ""}`}>
                    <td className="px-3 py-1.5">
                      <span className="text-gray-900">{r.name}</span>
                      <span className="ml-1 text-xs text-gray-400">{r.kind}</span>
                    </td>
                    <td className="px-2 py-1.5 text-gray-700">
                      {[...r.entra_roles, ...r.entra_permissions].slice(0, 4).join(", ") || "—"}
                    </td>
                    <td className="px-2 py-1.5 text-gray-700">
                      {r.azure_roles.length ? (
                        <span className="font-medium text-red-700">{r.azure_roles.join(", ")}</span>
                      ) : r.azure_all_roles ? (
                        <span className="text-gray-500">{r.azure_all_roles} role(s)</span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-xs text-gray-500">
                      {r.azure_broad_scopes.join(", ") || r.azure_subscriptions.slice(0, 2).join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
