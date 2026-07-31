import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type EntraCaPolicy, type EntraSimulationResult } from "../../api";
import { formatError } from "../../utils/format";
import { EntraEmpty } from "./EntraShared";

/**
 * Conditional Access Change Simulator.
 *
 * Diff-first by construction: this screen never says "here is what happens", it says "here is
 * what *changes*". Break-glass impact is rendered first and never collapsed, and every result
 * carries its confidence label and the model's published limitations — a bare verdict would be
 * worse than no simulator at all.
 */

const CATEGORY_META: { key: keyof EntraSimulationResult["counts"]; label: string; tone: string; blurb: string }[] = [
  { key: "newly_blocked", label: "Newly blocked", tone: "text-red-700",
    blurb: "Cannot satisfy the new control — a hard block, not friction." },
  { key: "protection_lost", label: "Protection lost", tone: "text-orange-700",
    blurb: "A control that used to apply no longer does. The silent risk of a cleanup." },
  { key: "newly_challenged", label: "Newly challenged", tone: "text-amber-700",
    blurb: "Can satisfy the control — will see an extra prompt." },
  { key: "newly_granted", label: "Newly granted", tone: "text-sky-700",
    blurb: "Access that was previously restricted." },
  { key: "unchanged", label: "Unchanged", tone: "text-gray-500", blurb: "" },
];

export function EntraSimulatorView({ connectionId }: { connectionId: string | null }) {
  const policiesQ = useQuery({
    queryKey: ["entra-ca-policies", connectionId],
    queryFn: () => api.entraCaPolicies(connectionId),
  });
  const contextsQ = useQuery({
    queryKey: ["entra-sim-contexts"],
    queryFn: () => api.entraSimulateContexts(),
  });
  const savedQ = useQuery({
    queryKey: ["entra-simulations", connectionId],
    queryFn: () => api.entraSimulations(connectionId),
  });

  const [changeKind, setChangeKind] = useState<"enable" | "disable" | "delete" | "report_only">("enable");
  const [policyId, setPolicyId] = useState("");
  const [contexts, setContexts] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<EntraSimulationResult | null>(null);

  const policies = policiesQ.data?.policies ?? [];
  const candidates = useMemo(() => {
    if (changeKind === "enable") return policies.filter((p) => !p.is_enforced);
    if (changeKind === "report_only") return policies.filter((p) => p.is_enforced);
    return policies.filter((p) => p.is_enforced || p.is_report_only);
  }, [policies, changeKind]);

  const run = async (save: boolean) => {
    if (!policyId) return;
    setRunning(true);
    setError("");
    try {
      const res = await api.entraSimulate(
        { changes: [{ kind: changeKind, policy_id: policyId }], contexts, save,
          label: `${changeKind} ${policies.find((p) => p.id === policyId)?.display_name ?? policyId}` },
        connectionId,
      );
      setResult(res.result);
      if (save) void savedQ.refetch();
    } catch (err) {
      setError(formatError(err));
    } finally {
      setRunning(false);
    }
  };

  if (policiesQ.isLoading) return <div className="p-6 text-sm text-gray-500">Loading policies…</div>;
  if (policiesQ.isError) return <div className="p-6 text-sm text-red-600">{formatError(policiesQ.error)}</div>;
  if (!policiesQ.data?.meta.loaded) return <EntraEmpty kind="cold" />;
  if (!policies.length) {
    // Zero Conditional Access policies is a serious gap, not a clean bill of health —
    // a green tick here would contradict the coverage tab sitting next to it.
    return (
      <div className="p-6">
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <div className="font-semibold">This tenant has no Conditional Access policies.</div>
          <div className="mt-1">
            There is nothing to simulate a change against — and nothing enforcing MFA, blocking
            legacy authentication or requiring compliant devices either. Start from the Coverage
            tab to see what is currently unprotected.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 p-4">
      {/* Change builder */}
      <div className="rounded-lg border bg-white p-3">
        <div className="mb-2 text-[13px] font-semibold text-gray-800">Proposed change</div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={changeKind}
            onChange={(e) => { setChangeKind(e.target.value as typeof changeKind); setPolicyId(""); }}
            className="rounded border px-2 py-1 text-sm"
          >
            <option value="enable">Enable</option>
            <option value="disable">Disable</option>
            <option value="report_only">Set to report-only</option>
            <option value="delete">Delete</option>
          </select>
          <select
            value={policyId}
            onChange={(e) => setPolicyId(e.target.value)}
            className="min-w-[22rem] rounded border px-2 py-1 text-sm"
          >
            <option value="">Select a policy…</option>
            {candidates.map((p: EntraCaPolicy) => (
              <option key={p.id} value={p.id}>
                {p.display_name} ({p.state})
              </option>
            ))}
          </select>
          <button
            onClick={() => void run(false)}
            disabled={!policyId || running}
            className="rounded bg-brand px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40"
          >
            {running ? "Simulating…" : "Simulate"}
          </button>
          <button
            onClick={() => void run(true)}
            disabled={!policyId || running}
            className="rounded border px-3 py-1.5 text-sm font-medium text-gray-700 disabled:opacity-40"
          >
            Simulate &amp; save
          </button>
        </div>

        {contextsQ.data && (
          <details className="mt-2">
            <summary className="cursor-pointer text-xs text-gray-500">
              Sign-in contexts ({contexts.length || contextsQ.data.contexts.length} selected)
            </summary>
            <div className="mt-1 flex flex-wrap gap-2">
              {contextsQ.data.contexts.map((c) => {
                const on = contexts.length === 0 || contexts.includes(c.key);
                return (
                  <label key={c.key} className="flex items-center gap-1 text-xs text-gray-600">
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={(e) =>
                        setContexts((prev) => {
                          const base = prev.length ? prev : contextsQ.data!.contexts.map((x) => x.key);
                          return e.target.checked ? [...new Set([...base, c.key])] : base.filter((k) => k !== c.key);
                        })
                      }
                    />
                    {c.label}
                  </label>
                );
              })}
            </div>
          </details>
        )}
        <div className="mt-2 text-[11px] text-gray-400">
          Nothing is written to the tenant. The simulator computes over the cached snapshot only.
        </div>
      </div>

      {error && <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>}

      {result && <SimulationResultCard result={result} />}

      {/* Saved simulations */}
      {(savedQ.data?.simulations.length ?? 0) > 0 && (
        <div className="rounded-lg border bg-white">
          <div className="border-b px-4 py-2 text-[13px] font-semibold text-gray-800">Saved simulations</div>
          <table className="w-full text-[13px]">
            <tbody>
              {savedQ.data!.simulations.map((s) => (
                <tr key={s.id} className="border-b last:border-b-0">
                  <td className="px-3 py-1.5 text-gray-900">{s.label}</td>
                  <td className="px-2 py-1.5 text-gray-500">{s.at?.slice(0, 16).replace("T", " ")}</td>
                  <td className="px-2 py-1.5 text-gray-600">
                    {s.counts.newly_blocked ?? 0} blocked · {s.counts.protection_lost ?? 0} protection lost
                  </td>
                  <td className="px-2 py-1.5">
                    {s.break_glass_affected > 0 && (
                      <span className="rounded bg-red-100 px-1.5 py-0.5 text-[11px] text-red-700">
                        {s.break_glass_affected} break-glass
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    {s.stale && <span className="mr-2 text-[11px] text-amber-600">based on older data</span>}
                    <button
                      onClick={async () => {
                        const res = await api.entraSimulationRerun(s.id, connectionId);
                        setResult(res.result);
                        void savedQ.refetch();
                      }}
                      className="text-xs font-medium text-brand underline underline-offset-2"
                    >
                      Re-run
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function SimulationResultCard({ result }: { result: EntraSimulationResult }) {
  return (
    <div className="space-y-3">
      {/* Break-glass impact is ALWAYS first and never collapsed. */}
      {result.break_glass_affected > 0 ? (
        <div className="rounded-lg border-2 border-red-400 bg-red-50 p-3">
          <div className="text-sm font-semibold text-red-800">
            ⚠ {result.break_glass_affected} break-glass account(s) would be newly blocked
          </div>
          <ul className="mt-1 space-y-0.5 text-[13px] text-red-800">
            {result.break_glass_impact.map((c, i) => (
              <li key={i}>
                {c.principal} — {c.context_label}
                {c.missing.length > 0 && ` · cannot satisfy ${c.missing.join(", ")}`}
              </li>
            ))}
          </ul>
          <div className="mt-1 text-xs text-red-700">
            This is the account that exists to recover the tenant. Exclude it before enforcing.
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-[13px] text-green-800">
          ✓ No confirmed break-glass account is newly blocked by this change.
        </div>
      )}

      <div className="rounded-lg border bg-white p-3">
        <div className="mb-2 flex items-center gap-2">
          <span className="text-[13px] font-semibold text-gray-800">Impact</span>
          <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] text-gray-600">
            {result.confidence_label}
          </span>
          <span className="text-xs text-gray-500">
            {result.changes.join(", ")} · baseline {result.baseline_enforced} → {result.proposed_enforced} enforced
          </span>
        </div>
        <div className="grid gap-2 md:grid-cols-5">
          {CATEGORY_META.map((c) => (
            <div key={c.key} className="rounded border p-2" title={c.blurb}>
              <div className={`text-lg font-semibold ${c.tone}`}>
                {(result.counts[c.key] ?? 0).toLocaleString()}
              </div>
              <div className="text-[11px] text-gray-500">{c.label}</div>
            </div>
          ))}
        </div>

        {result.assumptions.mfa_unknown_principals > 0 && (
          <div className="mt-2 rounded bg-amber-50 px-2 py-1 text-xs text-amber-800">
            {result.assumptions.mfa_unknown_note}
          </div>
        )}
        {result.sampling.sampled && (
          <div className="mt-2 text-xs text-gray-500">
            Evaluated {result.sampling.evaluated.toLocaleString()} of{" "}
            {result.sampling.total_principals.toLocaleString()} principals (seeded sample). Break-glass,
            Global Administrator and all privileged accounts are always evaluated in full.
          </div>
        )}
      </div>

      {result.cases.length > 0 && (
        <div className="overflow-hidden rounded-lg border bg-white">
          <div className="border-b px-4 py-2 text-[13px] font-semibold text-gray-800">
            Changed outcomes ({result.case_total.toLocaleString()})
          </div>
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b bg-gray-50 text-left text-xs text-gray-500">
                <th className="px-3 py-2 font-medium">Principal</th>
                <th className="px-2 py-2 font-medium">Context</th>
                <th className="px-2 py-2 font-medium">Before</th>
                <th className="px-2 py-2 font-medium">After</th>
                <th className="px-2 py-2 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody>
              {result.cases.map((c, i) => (
                <tr key={i} className="border-b last:border-b-0">
                  <td className="px-3 py-1.5">
                    <span className="text-gray-900">{c.principal}</span>
                    {c.cohorts.includes("break_glass") && (
                      <span className="ml-1 rounded bg-red-100 px-1 py-0.5 text-[10px] text-red-700">break-glass</span>
                    )}
                    {c.kind === "servicePrincipal" && (
                      <span className="ml-1 text-[10px] text-gray-400">workload</span>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-gray-600">{c.context_label}</td>
                  <td className="px-2 py-1.5 text-gray-500">{c.from}</td>
                  <td className={`px-2 py-1.5 font-medium ${
                    c.category === "newly_blocked" ? "text-red-700"
                      : c.category === "protection_lost" ? "text-orange-700" : "text-amber-700"}`}>
                    {c.to}
                  </td>
                  <td className="px-2 py-1.5 text-xs text-gray-500">
                    {c.missing.length ? `cannot satisfy ${c.missing.join(", ")}` : c.category.replace(/_/g, " ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* An honest limitation list is what makes the tool trustworthy. */}
      <details className="rounded-lg border bg-white p-3">
        <summary className="cursor-pointer text-[13px] font-semibold text-gray-800">
          What this model does not cover
        </summary>
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs text-gray-600">
          {result.limitations.map((l) => <li key={l}>{l}</li>)}
        </ul>
      </details>
    </div>
  );
}
