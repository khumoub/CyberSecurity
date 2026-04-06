'use client';
/**
 * Centralised react-query hooks for all API calls.
 * Import from here instead of calling api directly in components.
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from './api';
import { useAuthStore } from './auth';

function useOrgId() {
  return useAuthStore((s) => s.user?.org_id ?? '');
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export function useDashboardStats() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['dashboard', 'stats', orgId],
    queryFn: () => api.get(`/dashboard/stats?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
    refetchInterval: 30_000,
  });
}

export function useDashboardMttr() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['dashboard', 'mttr', orgId],
    queryFn: () => api.get(`/dashboard/mttr?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

// ── Assets ───────────────────────────────────────────────────────────────────
export function useAssets(params?: Record<string, string>) {
  const orgId = useOrgId();
  const qs = new URLSearchParams({ org_id: orgId, ...params }).toString();
  return useQuery({
    queryKey: ['assets', orgId, params],
    queryFn: () => api.get(`/assets?${qs}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useCreateAsset() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/assets', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets', orgId] }),
  });
}

export function useImportAssets() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/assets/import', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets', orgId] }),
  });
}

export function useDeleteAsset() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: (id: string) => api.delete(`/assets/${id}`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets', orgId] }),
  });
}

// ── Scans ────────────────────────────────────────────────────────────────────
export function useScans(params?: Record<string, string>) {
  const orgId = useOrgId();
  const qs = new URLSearchParams({ org_id: orgId, ...params }).toString();
  return useQuery({
    queryKey: ['scans', orgId, params],
    queryFn: () => api.get(`/scans?${qs}`).then((r) => r.data),
    enabled: !!orgId,
    refetchInterval: 10_000,
  });
}

export function useCreateScan() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/scans', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans', orgId] }),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${id}`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans', orgId] }),
  });
}

// ── Findings ─────────────────────────────────────────────────────────────────
export function useFindings(params?: Record<string, string>) {
  const orgId = useOrgId();
  const qs = new URLSearchParams({ org_id: orgId, ...params }).toString();
  return useQuery({
    queryKey: ['findings', orgId, params],
    queryFn: () => api.get(`/findings?${qs}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useFindingStats() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['findings', 'stats', orgId],
    queryFn: () => api.get(`/findings/stats?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useUpdateFinding() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      api.patch(`/findings/${id}`, data).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings', orgId] });
      qc.invalidateQueries({ queryKey: ['dashboard', 'stats', orgId] });
    },
  });
}

// ── Remediation ───────────────────────────────────────────────────────────────
export function useRemediationTasks(params?: Record<string, string>) {
  const orgId = useOrgId();
  const qs = new URLSearchParams({ org_id: orgId, ...params }).toString();
  return useQuery({
    queryKey: ['remediation', orgId, params],
    queryFn: () => api.get(`/remediation?${qs}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useRemediationStats() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['remediation', 'stats', orgId],
    queryFn: () => api.get(`/remediation/stats/summary?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useUpdateRemediationTask() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      api.patch(`/remediation/${id}`, data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation', orgId] }),
  });
}

// ── Intel / Risk ──────────────────────────────────────────────────────────────
export function useRiskScores() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['intel', 'risk-scores', orgId],
    queryFn: () => api.get(`/intel/risk-scores?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useCisaKev(page = 1) {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['intel', 'cisa-kev', orgId, page],
    queryFn: () => api.get(`/intel/cisa-kev?org_id=${orgId}&page=${page}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useRiskHeatmap() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['intel', 'heatmap', orgId],
    queryFn: () => api.get(`/intel/risk-heatmap?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function usePatchPriority() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['intel', 'patch-priority', orgId],
    queryFn: () => api.get(`/intel/patch-priority-ai?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

// ── MITRE ─────────────────────────────────────────────────────────────────────
export function useMitreCoverage() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['mitre', 'coverage', orgId],
    queryFn: () => api.get(`/mitre/coverage?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

// ── TPRM / Vendors ────────────────────────────────────────────────────────────
export function useVendors() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['tprm', 'vendors', orgId],
    queryFn: () => api.get(`/tprm/vendors?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useCreateVendor() {
  const qc = useQueryClient();
  const orgId = useOrgId();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/tprm/vendors', data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tprm', 'vendors', orgId] }),
  });
}

export function useGenerateQuestionnaire() {
  return useMutation({
    mutationFn: (vendorId: string) =>
      api.post(`/tprm/vendors/${vendorId}/generate-questionnaire`).then((r) => r.data),
  });
}

export function useComplianceMapping(framework: string) {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['tprm', 'compliance', orgId, framework],
    queryFn: () => api.get(`/tprm/compliance/mapping?org_id=${orgId}&framework=${framework}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

// ── Tools ─────────────────────────────────────────────────────────────────────
export function useRunTool() {
  return useMutation({
    mutationFn: ({ tool, body }: { tool: string; body: Record<string, unknown> }) =>
      api.post(`/tools/${tool}`, body).then((r) => r.data),
  });
}

// ── Intel ─────────────────────────────────────────────────────────────────────
export function useAttackPaths() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['intel', 'attack-paths', orgId],
    queryFn: () => api.get(`/intel/attack-paths?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useWordlists() {
  return useQuery({
    queryKey: ['tools', 'wordlists'],
    queryFn: () => api.get('/tools/wordlists').then((r) => r.data),
  });
}

// ── Billing ───────────────────────────────────────────────────────────────────
export function useBillingPlans() {
  return useQuery({
    queryKey: ['billing', 'plans'],
    queryFn: () => api.get('/billing/plans').then((r) => r.data),
  });
}

export function useSubscription() {
  return useQuery({
    queryKey: ['billing', 'subscription'],
    queryFn: () => api.get('/billing/subscription').then((r) => r.data),
  });
}

// ── Reports ───────────────────────────────────────────────────────────────────
export function useScheduledReports() {
  return useQuery({
    queryKey: ['reports', 'scheduled'],
    queryFn: () => api.get('/reports/scheduled').then((r) => r.data),
  });
}

export function useGenerateReport() {
  return useMutation({
    mutationFn: ({ type, options }: { type: 'executive' | 'technical'; options: Record<string, unknown> }) =>
      api.post(`/reports/${type}-pdf`, options, { responseType: 'blob' }).then((r) => r.data),
    onSuccess: (blob, { type }) => {
      const url = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `leruo-${type}-report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    },
  });
}

// ── Webhooks ──────────────────────────────────────────────────────────────────
export function useWebhooks() {
  return useQuery({
    queryKey: ['webhooks'],
    queryFn: () => api.get('/webhooks').then((r) => r.data),
  });
}

// ── Scan Policies ─────────────────────────────────────────────────────────────
export function useScanPolicies() {
  return useQuery({
    queryKey: ['scan-policies'],
    queryFn: () => api.get('/scan-policies/').then((r) => r.data),
  });
}

export function useCreateScanPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/scan-policies/', body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-policies'] }),
  });
}

export function useUpdateScanPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string } & Record<string, unknown>) =>
      api.patch(`/scan-policies/${id}`, body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-policies'] }),
  });
}

export function useDeleteScanPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete(`/scan-policies/${id}`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-policies'] }),
  });
}

export function useRunScanPolicyNow() {
  return useMutation({
    mutationFn: (id: string) => api.post(`/scan-policies/${id}/run-now`).then((r) => r.data),
  });
}

export function useScanPolicyPresets() {
  return useQuery({
    queryKey: ['scan-policies', 'presets'],
    queryFn: () => api.get('/scan-policies/presets/list').then((r) => r.data),
  });
}

// ── Integrations ──────────────────────────────────────────────────────────────
export function useIntegrationStatus() {
  return useQuery({
    queryKey: ['integrations', 'status'],
    queryFn: () => api.get('/integrations/status').then((r) => r.data),
  });
}

export function useJiraConfig() {
  return useQuery({
    queryKey: ['integrations', 'jira', 'config'],
    queryFn: () => api.get('/integrations/jira/config').then((r) => r.data),
  });
}

export function useSaveJiraConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.put('/integrations/jira/config', body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations'] }),
  });
}

export function useCreateJiraIssue() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { finding_id: string; summary_override?: string; assignee?: string }) =>
      api.post('/integrations/jira/issues', body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations', 'jira', 'issues'] }),
  });
}

export function useJiraIssues() {
  return useQuery({
    queryKey: ['integrations', 'jira', 'issues'],
    queryFn: () => api.get('/integrations/jira/issues').then((r) => r.data),
  });
}

export function useSyncJiraStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (finding_id: string) => api.post(`/integrations/jira/sync/${finding_id}`).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations', 'jira', 'issues'] }),
  });
}

export function useSlackConfig() {
  return useQuery({
    queryKey: ['integrations', 'slack', 'config'],
    queryFn: () => api.get('/integrations/slack/config').then((r) => r.data),
  });
}

export function useSaveSlackConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.put('/integrations/slack/config', body).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations'] }),
  });
}

export function useSendSlackAlert() {
  return useMutation({
    mutationFn: (finding_id: string) => api.post('/integrations/slack/alert', { finding_id }).then((r) => r.data),
  });
}

// ── Intel: VPR + Attack Path Chains ──────────────────────────────────────────
export function useVprScores(limit = 50) {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['intel', 'vpr', orgId, limit],
    queryFn: () => api.get(`/intel/vpr?org_id=${orgId}&limit=${limit}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

export function useAttackPathChains() {
  const orgId = useOrgId();
  return useQuery({
    queryKey: ['intel', 'attack-path-chains', orgId],
    queryFn: () => api.get(`/intel/attack-path-chains?org_id=${orgId}`).then((r) => r.data),
    enabled: !!orgId,
  });
}

// ── Compliance Reports ────────────────────────────────────────────────────────
export function useComplianceFrameworks() {
  return useQuery({
    queryKey: ['reports', 'compliance', 'frameworks'],
    queryFn: () => api.get('/reports/compliance/frameworks').then((r) => r.data),
  });
}

export function useGenerateComplianceReport() {
  return useMutation({
    mutationFn: ({ framework, options }: { framework: string; options: Record<string, unknown> }) =>
      api.post(`/reports/compliance/${framework}`, options).then((r) => r.data),
    onSuccess: (data) => {
      if (data.html_base64) {
        const html = atob(data.html_base64);
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = data.filename || 'compliance-report.html';
        a.click();
        URL.revokeObjectURL(url);
      }
    },
  });
}

// ── New Tool Mutations ────────────────────────────────────────────────────────
export function useRunCredentialedScan() {
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/tools/credentialed-scan', body).then((r) => r.data),
  });
}

export function useRunExploitVerify() {
  return useMutation({
    mutationFn: (body: { finding_id: string; target?: string; authorized: boolean }) =>
      api.post('/tools/exploit-verify', body).then((r) => r.data),
  });
}

export function useRunAdAttacks() {
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/tools/ad-attacks', body).then((r) => r.data),
  });
}

export function useRunFixVerify() {
  return useMutation({
    mutationFn: (body: { finding_id: string; target?: string }) =>
      api.post('/tools/fix-verify', body).then((r) => r.data),
  });
}

export function useRunContainerScan() {
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/tools/container-scan', body).then((r) => r.data),
  });
}

export function useRunCisAudit() {
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/tools/cis-audit', body).then((r) => r.data),
  });
}

export function useRunEasm() {
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/tools/easm', body).then((r) => r.data),
  });
}
