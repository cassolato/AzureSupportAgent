import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api";
import type { EntraAccessReview } from "../../api";
import { formatError } from "../../utils/format";
import { Bar, CoverageBanner, EntraEmpty, SevBadge } from "./EntraShared";

type Tab = "coverage" | "reviews" | "entitlement" | "lifecycle";

const TABS: { id: Tab; label: string }[] = [
  { id: "coverage", label: "Coverage" },
  { id: "reviews", label: "Access reviews" },
  { id: "entitlement", label: "Entitlement" },
  { id: "lifecycle", label: "Lifecycle" },
];

const FLAG_TEXT: Record<string, string> = {
  decisions_not_applied: "Decisions are not applied automatically — a denial removes nothing.",
  default_approve: "Inaction approves. This campaign can only confirm the status quo.",
  not_recurring: "Runs once. Accurate the day it closes, wrong the following week.",
  no_justification: "Reviewers are not asked to justify a decision.",
  self_review: "The reviewer is the subject of the review.",
};

function Unlicensed({ what, why }: { what: string; why: string }) {
  return (
    <div className="p-6">
      <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 text-sm text-gray-700">
        <div className="font-semibold text-gray-900">{what}</div>
        <div className="mt-1">{why}</div>
      </div>
    </div>
  );
}

function CoverageTab({ connectionId }: { connectionId: string | null }) {
  const q = useQuery({
    queryKey: ["entra-gov-coverage", connectionId],
    queryFn: () => api.entraGovernanceCoverage(connectionId),
  });
  const [open, setOpen] = useState<string>("");
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Computing governance coverage…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;
  const totalGap = d.rows.reduce((a, r) => a + r.gap, 0);
  return (
    <div className="space-y-4 p-4">
      <div className="rounded border border-sky-200 bg-sky-50 px-3 py-2 text-xs text-sky-900">
        The portal shows the reviews you have. This table shows what nothing is reviewing —
        computed from the inventory, so it works whether or not this tenant is licensed for
        access reviews.
        {!d.governance_readable && (
          <span className="mt-1 block font-medium">
            Access reviews could not be read for this tenant, so every object below counts as
            unreviewed. That is the correct assumption when no review data exists.
          </span>
        )}
      </div>

      <div className="rounded-lg border bg-white">
        <table className="w-full text-[13px]">
          <thead className="text-left text-[11px] uppercase tracking-wide text-gray-500">
            <tr className="border-b">
              <th className="px-3 py-1.5">Object class</th>
              <th>Count</th><th>Reviewed</th><th>Governed by package</th>
              <th className="pr-3">Gap</th>
            </tr>
          </thead>
          <tbody>
            {d.rows.map((r) => (
              <Fragment key={r.key}>
                <tr className="cursor-pointer border-b last:border-b-0 hover:bg-gray-50"
                    onClick={() => setOpen(open === r.key ? "" : r.key)}>
                  <td className="px-3 py-2">
                    <div className="text-gray-900">{r.label}</div>
                    <div className="text-[11px] text-gray-500">{r.why}</div>
                  </td>
                  <td>{r.count.toLocaleString()}</td>
                  <td className={r.reviewed ? "text-green-700" : "text-gray-400"}>{r.reviewed.toLocaleString()}</td>
                  <td className={r.governed ? "text-green-700" : "text-gray-400"}>{r.governed.toLocaleString()}</td>
                  <td className="pr-3">
                    <div className="flex items-center gap-2">
                      <Bar value={r.gap} max={Math.max(r.count, 1)}
                           tone={r.gap ? "bg-red-400" : "bg-green-400"} />
                      <span className={`w-12 text-right font-medium ${r.gap ? "text-red-600" : "text-green-700"}`}>
                        {r.gap.toLocaleString()}
                      </span>
                    </div>
                  </td>
                </tr>
                {open === r.key && (
                  <tr className="border-b bg-gray-50">
                    <td colSpan={5} className="px-3 py-2">
                      <div className="text-[11px] uppercase tracking-wide text-gray-500">
                        Objects in this class
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {r.objects.length ? r.objects.map((o) => (
                          <span key={o} className="rounded bg-white px-1.5 py-0.5 text-[11px] text-gray-700 ring-1 ring-gray-200">
                            {o}
                          </span>
                        )) : <span className="text-xs text-gray-500">None in this tenant.</span>}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <div className="text-xs text-gray-500">
        {totalGap
          ? `${totalGap} object(s) across ${d.rows.filter((r) => r.gap).length} class(es) are governed by nothing.`
          : "Every object class is covered by a review or an access package."}
      </div>
    </div>
  );
}

function ReviewsTab({ connectionId }: { connectionId: string | null }) {
  const [overdue, setOverdue] = useState(false);
  const q = useQuery({
    queryKey: ["entra-gov-reviews", connectionId, overdue],
    queryFn: () => api.entraReviews(overdue, connectionId),
  });
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Loading access reviews…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;
  if (!d.capabilities.access_reviews) {
    return <Unlicensed what="Access reviews are not available"
                       why="Access reviews require Entra ID P2 and AccessReview.Read.All. The Coverage tab still tells you what is unreviewed." />;
  }
  return (
    <div className="space-y-3 p-4">
      <label className="flex items-center gap-2 text-[13px] text-gray-700">
        <input type="checkbox" checked={overdue} onChange={(e) => setOverdue(e.target.checked)} />
        Overdue only
      </label>
      {d.reviews.map((r: EntraAccessReview) => (
        <div key={r.id} className="rounded-lg border bg-white p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-gray-900">{r.display_name}</span>
            <span className="text-[11px] text-gray-500">{r.status} · {r.recurrence}</span>
            {r.days_overdue > 0 && (
              <span className="rounded bg-red-100 px-1.5 py-0.5 text-[11px] font-medium text-red-700">
                {r.days_overdue}d overdue
              </span>
            )}
            {r.scope?.kind && (
              <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] text-gray-600">
                scope: {r.scope.kind}
              </span>
            )}
          </div>
          {r.quality_flags.length ? (
            <ul className="mt-2 space-y-0.5">
              {r.quality_flags.map((f) => (
                <li key={f} className="text-[12px] text-amber-800">• {FLAG_TEXT[f] || f}</li>
              ))}
            </ul>
          ) : (
            <div className="mt-1 text-[12px] text-green-700">
              No configuration problems: recurring, auto-applied and justified.
            </div>
          )}
        </div>
      ))}
      {!d.reviews.length && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          {overdue ? "No review is overdue." : "This tenant has no access reviews at all. The Coverage tab lists what that leaves unreviewed."}
        </div>
      )}
    </div>
  );
}

function EntitlementTab({ connectionId }: { connectionId: string | null }) {
  const q = useQuery({
    queryKey: ["entra-gov-entitlement", connectionId],
    queryFn: () => api.entraEntitlement(30, connectionId),
  });
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Loading entitlement management…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;
  if (!d.capabilities.entitlement) {
    return <Unlicensed what="Entitlement management is not available"
                       why="Access packages require Entra ID P2 and EntitlementManagement.Read.All." />;
  }
  return (
    <div className="space-y-4 p-4">
      <div className="rounded-lg border bg-white">
        <div className="border-b px-3 py-1.5 text-[13px] font-semibold text-gray-800">
          Access packages ({d.packages.length})
        </div>
        <table className="w-full text-[13px]">
          <thead className="text-left text-[11px] uppercase tracking-wide text-gray-500">
            <tr className="border-b"><th className="px-3 py-1.5">Package</th><th>Resources</th>
              <th>Policies</th><th className="pr-3">Hygiene</th></tr>
          </thead>
          <tbody>
            {d.packages.map((p) => (
              <tr key={p.id} className="border-b last:border-b-0">
                <td className="px-3 py-1.5">
                  <div className="text-gray-900">{p.display_name}</div>
                  {/* Most tenants paste the name into the description; printing it twice
                      looks like a rendering fault. */}
                  {p.description && p.description.trim() !== p.display_name.trim() && (
                    <div className="text-[11px] text-gray-500">{p.description}</div>
                  )}
                </td>
                <td>{p.resource_scopes}</td>
                <td>{p.policies.length}</td>
                <td className="pr-3">
                  <div className="flex flex-wrap gap-1">
                    {p.no_review && (
                      <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] text-amber-800">
                        no review
                      </span>
                    )}
                    {p.no_expiry && (
                      <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] text-amber-800">
                        never expires
                      </span>
                    )}
                    {!p.no_review && !p.no_expiry && (
                      <span className="text-[11px] text-green-700">reviewed and time-bound</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {!d.packages.length && (
              <tr><td colSpan={4} className="py-3 text-center text-xs text-gray-500">
                No access packages defined.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="rounded-lg border bg-white p-3">
        <div className="mb-2 text-[13px] font-semibold text-gray-800">
          Expiring within 30 days ({d.expiring.length} of {d.assignments_total} assignment(s))
        </div>
        {d.expiring.length ? d.expiring.map((a) => (
          <div key={a.id} className="flex items-center justify-between border-b py-1 text-[13px] last:border-b-0">
            <span className="text-gray-800">{a.principal_name} → {a.package_name}</span>
            <span className={a.days_left <= 7 ? "text-amber-700" : "text-gray-500"}>
              {a.days_left}d
            </span>
          </div>
        )) : (
          <div className="text-xs text-gray-500">Nothing expires in the next 30 days.</div>
        )}
      </div>
    </div>
  );
}

function LifecycleTab({ connectionId }: { connectionId: string | null }) {
  const q = useQuery({
    queryKey: ["entra-gov-lifecycle", connectionId],
    queryFn: () => api.entraLifecycle(connectionId),
  });
  if (q.isLoading) return <div className="p-6 text-sm text-gray-500">Loading lifecycle workflows…</div>;
  if (q.isError) return <div className="p-6 text-sm text-red-600">{formatError(q.error)}</div>;
  const d = q.data!;
  if (!d.meta.loaded) return <EntraEmpty kind="cold" />;
  if (!d.capabilities.lifecycle) {
    return <Unlicensed what="Lifecycle workflows are not available"
                       why="Lifecycle workflows require the Entra ID Governance licence and LifecycleWorkflows.Read.All." />;
  }
  return (
    <div className="space-y-4 p-4">
      {d.missing_categories.length > 0 && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          <span className="font-semibold">
            No enabled {d.missing_categories.join(" or ")} workflow.
          </span>{" "}
          {d.missing_categories.includes("leaver") &&
            "Offboarding is manual, which means it depends on somebody remembering every system."}
        </div>
      )}
      <div className="rounded-lg border bg-white">
        <table className="w-full text-[13px]">
          <thead className="text-left text-[11px] uppercase tracking-wide text-gray-500">
            <tr className="border-b"><th className="px-3 py-1.5">Workflow</th><th>Category</th>
              <th>Enabled</th><th>Tasks</th><th>Runs</th><th className="pr-3">Failure rate</th></tr>
          </thead>
          <tbody>
            {d.workflows.map((w) => (
              <tr key={w.id} className="border-b last:border-b-0">
                <td className="px-3 py-1.5 text-gray-900">{w.display_name}</td>
                <td>{w.category}</td>
                <td className={w.enabled ? "text-green-700" : "text-amber-700"}>
                  {w.enabled ? "yes" : "no"}
                </td>
                <td>{w.task_count}</td>
                <td>{w.runs.total}</td>
                <td className="pr-3">
                  <div className="flex items-center gap-2">
                    <Bar value={w.runs.failed} max={Math.max(w.runs.total, 1)}
                         tone={w.runs.failed ? "bg-red-400" : "bg-green-400"} />
                    <span className={w.runs.failed ? "text-red-600" : "text-gray-500"}>
                      {(w.failure_rate * 100).toFixed(0)}%
                    </span>
                  </div>
                </td>
              </tr>
            ))}
            {!d.workflows.length && (
              <tr><td colSpan={6} className="py-3 text-center text-xs text-gray-500">
                No lifecycle workflows are configured.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function EntraGovernanceView({ connectionId, onOpenSetup }:
  { connectionId: string | null; onOpenSetup?: () => void }) {
  const [tab, setTab] = useState<Tab>("coverage");
  const overviewQ = useQuery({
    queryKey: ["entra-gov-overview", connectionId],
    queryFn: () => api.entraGovernanceOverview(connectionId),
  });
  return (
    <div className="flex h-full min-h-0 flex-col">
      {overviewQ.data && (
        <CoverageBanner meta={overviewQ.data.meta} onOpenSetup={onOpenSetup} />
      )}
      <div className="flex shrink-0 items-center gap-1 border-b bg-white px-3 pt-2">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
                  className={`rounded-t px-3 py-1.5 text-[13px] ${
                    tab === t.id ? "border border-b-white bg-white font-medium text-gray-900"
                                 : "text-gray-600 hover:text-gray-900"}`}>
            {t.label}
          </button>
        ))}
        {overviewQ.data?.findings?.length ? (
          <span className="ml-auto flex items-center gap-1 pb-1 text-[11px] text-gray-500">
            <SevBadge sev="high" /> {overviewQ.data.findings.length} governance finding(s)
          </span>
        ) : null}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {tab === "coverage" && <CoverageTab connectionId={connectionId} />}
        {tab === "reviews" && <ReviewsTab connectionId={connectionId} />}
        {tab === "entitlement" && <EntitlementTab connectionId={connectionId} />}
        {tab === "lifecycle" && <LifecycleTab connectionId={connectionId} />}
      </div>
    </div>
  );
}
