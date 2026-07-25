import { QueryClient } from "@tanstack/react-query";
import { queryKeys } from "./queryKeys";

// Shared singleton QueryClient. Lives in its own module (no component imports) so that
// non-component modules — e.g. the Performance Profiler's background-run registry — can
// invalidate queries without creating a circular import with main.tsx.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Treat data as fresh for 30s so navigating between views doesn't re-hit the
      // API for config/chats/connections on every mount (the previous default of 0
      // caused a refetch storm). Mutations still invalidate explicitly when needed.
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

// Per-key defaults for shared, low-churn data that many panels mount. These keys are
// requested by 5–10 components across the app; without a longer staleTime each mount
// triggers a refetch. Mutations still invalidate explicitly, so freshness is preserved.
const FIVE_MIN = 5 * 60_000;
const TEN_MIN = 10 * 60_000;
const LOW_CHURN_FIVE_MIN: readonly (readonly unknown[])[] = [
  ["workloads"],
  ["connectors"],
  queryKeys.azureConnections,
  ["adminConnections"],
  ["llmConfig"],
  ["activeLlm"],
  ["customAgents"],
  ["architectureCollections"],
  ["architectureCatalog"],
  ["assessmentCatalog"],
  ["assessmentPortfolio"],
  ["architectureMemories"],
];
const VERY_LOW_CHURN_TEN_MIN: readonly (readonly unknown[])[] = [
  ["me"],
  ["memoryCatalog"],
  ["builtinTools"],
  ["entraTools"],
  ["tools"],
  ["appSettings"],
  ["architectureCatalog"],
  ["monitorDatasources"],
];
for (const key of LOW_CHURN_FIVE_MIN) {
  queryClient.setQueryDefaults(key, { staleTime: FIVE_MIN });
}
for (const key of VERY_LOW_CHURN_TEN_MIN) {
  queryClient.setQueryDefaults(key, { staleTime: TEN_MIN });
}

// Operator-controlled analyses. These are expensive server-side sweeps whose results must
// only change when the operator explicitly asks — never on mount, focus, reconnect, or a
// staleness timer. Setting this here rather than at the call sites means the guarantee cannot
// be lost by a future component forgetting one of the options.
const OPERATOR_REFRESHED: readonly (readonly unknown[])[] = [
  queryKeys.backupManager.snapshotRoot,
];
for (const key of OPERATOR_REFRESHED) {
  queryClient.setQueryDefaults(key, {
    staleTime: Infinity,
    gcTime: Infinity,
    refetchOnMount: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
}

