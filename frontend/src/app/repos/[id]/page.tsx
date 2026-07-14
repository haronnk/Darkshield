'use client';

import React, { useEffect, useState, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { 
  ArrowLeft, 
  ExternalLink, 
  Play, 
  Trash2, 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  ChevronDown, 
  ChevronUp, 
  Copy, 
  Check, 
  Info,
  Clock,
  Terminal,
  Database
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { api, Repo, Finding, ScoreResponse, ReportPayload } from '@/lib/api';

const SCAN_STEPS = [
  { label: 'Cloning repository', duration: 3000 },
  { label: 'Scanning for secrets (pattern + entropy)', duration: 4000 },
  { label: 'Scanning git history', duration: 5000 },
  { label: 'Running static analysis (Semgrep)', duration: 6000 },
  { label: 'Scanning dependencies (Trivy)', duration: 6000 },
  { label: 'Generating AI risk summary', duration: 4000 },
  { label: 'Signing report', duration: 2000 }
];

export default function RepoDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [repo, setRepo] = useState<Repo | null>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [dataset, setDataset] = useState<any | null>(null);
  const [scoreData, setScoreData] = useState<ScoreResponse | null>(null);
  
  // Loading & Scanning States
  const [isLoading, setIsLoading] = useState(true);
  const [isError, setIsError] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStepIndex, setScanStepIndex] = useState(0);
  const [scanError, setScanError] = useState('');

  // Signed Report Verification States
    const [reportText, setReportText] = useState('');
    const [reportSignature, setReportSignature] = useState('');
    const [signedReportLoaded, setSignedReportLoaded] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<'idle' | 'valid' | 'invalid'>('idle');
  const [isReportCollapsed, setIsReportCollapsed] = useState(false);
  const [copiedSig, setCopiedSig] = useState(false);

  // Filters & Sorting
  const [sourceFilter, setSourceFilter] = useState<'all' | 'secrets' | 'semgrep' | 'trivy' | 'codeql'>('all');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('all');
  const [sortBy, setSortBy] = useState<'severity' | 'exposure'>('severity');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  // OWASP collapsible
  const [isOwaspCollapsed, setIsOwaspCollapsed] = useState(true);

  const fetchAllData = async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
    try {
      // 1. Fetch repos to find this repository
      const reposList = await api.listRepos();
      const currentRepo = reposList.find(r => r.id === id);
      if (!currentRepo) {
        setIsError(true);
        setIsLoading(false);
        return;
      }
      setRepo(currentRepo);

      // 2. Fetch findings
      const findingsDataset = await api.getFindings(id);
      setDataset(findingsDataset);

      const mappedFindings = findingsDataset.findings.map((f: any) => ({
        file_path: f.file,
        line_number: f.line,
        snippet: f.code_snippet,
        secret_hash: f.id,
        secret_type: f.title,
        severity: f.severity,
        cluster_id: null,
        source_type: f.scanner === 'secrets' ? 'pattern' : f.scanner,
        rule_id: f.scanner_rule,
        rule_name: f.title,
        owasp_category: f.owasp,
        vulnerability_description: f.description,
        recommendation: f.recommendation,
        status: f.status,
        confidence: f.confidence,
        supporting_scanners: f.supporting_scanners,
        code_flow: f.code_flow,
        occurrences: f.occurrences.map((o: any) => ({
          file_path: o.file_path,
          line_number: o.line_number,
          found_in: o.found_in,
          commit_hash: o.commit_hash
        }))
      }));
      setFindings(mappedFindings);

      // 3. Fetch security score
      const scoreRes = await api.getScore(id);
      setScoreData(scoreRes);

      // 4. Initialize report JSON from existing values if status is complete
        if (currentRepo.status === 'done') {
          const critCount = findingsDataset.findings.filter((f: any) => f.severity === 'CRITICAL').length;
          const payload: ReportPayload = currentRepo.report_payload || {
            repo_id: currentRepo.id,
            owner: currentRepo.owner,
            name: currentRepo.name,
            github_url: currentRepo.github_url,
            total_findings: findingsDataset.findings.length,
            critical_findings: critCount,
            generated_at: currentRepo.last_scanned_at || new Date().toISOString()
          };
          setReportText(JSON.stringify(payload, null, 2));
          // Retrieve signature from backend response (stored in repos table during scan update)
          const dbRepo = currentRepo as any;
          setReportSignature(dbRepo.report_signature || '');
          setVerifyResult('idle');
          setSignedReportLoaded(false);

          try {
            const signed = await api.getSignedReport(id);
            if (signed?.report && signed?.signature) {
              setReportText(JSON.stringify(signed.report, null, 2));
              setReportSignature(signed.signature);
              setSignedReportLoaded(true);
            }
          } catch (err) {
            console.warn('Falling back to reconstructed report payload', err);
          }
        }

      setIsError(false);
    } catch (err) {
      console.error(err);
      setIsError(true);
    } finally {
      if (showLoading) setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, [id]);

  const handleScan = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanStepIndex(0);
    setScanError('');
    setVerifyResult('idle');

    // Start simulated progress bar
    let currentStep = 0;
    const intervalTime = 100; // Check every 100ms
    let elapsedForStep = 0;

    const timer = setInterval(() => {
      const stepConfig = SCAN_STEPS[currentStep];
      if (!stepConfig) {
        clearInterval(timer);
        return;
      }

      elapsedForStep += intervalTime;
      if (elapsedForStep >= stepConfig.duration) {
        elapsedForStep = 0;
        if (currentStep < SCAN_STEPS.length - 1) {
          currentStep += 1;
          setScanStepIndex(currentStep);
        }
      }
    }, intervalTime);

    try {
      // Direct API call
      const res = await api.scanRepo(id);
      
      // Complete stepper instantly once done
      clearInterval(timer);
      setScanStepIndex(SCAN_STEPS.length - 1);
      
        // Update local state details
        setReportText(JSON.stringify(res.report_payload, null, 2));
        setReportSignature(res.report_signature);
        setSignedReportLoaded(true);
        
        // Refresh database records
        await fetchAllData(false);
    } catch (err: any) {
      clearInterval(timer);
      setScanError(err.message || 'Scanning encountered a critical execution failure.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const parsed = JSON.parse(reportText.trim());
      const res = await api.verifyReport({
        report: parsed,
        signature: reportSignature
      });
      setVerifyResult(res.valid ? 'valid' : 'invalid');
    } catch (err) {
      setVerifyResult('invalid');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm('Permanently delete this repository and all scanned findings?')) {
      return;
    }
    try {
      await api.deleteRepo(id);
      router.push('/');
    } catch (err) {
      alert('Delete failed.');
    }
  };

  const toggleExpandFinding = (key: string) => {
    setExpandedFindings(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  // Recharts Gauge representation
  const gaugeData = useMemo(() => {
    const score = scoreData?.security_score ?? 100;
    return [
      { name: 'Score', value: score },
      { name: 'Remaining', value: 100 - score }
    ];
  }, [scoreData]);

  const getGaugeColor = (score: number) => {
    if (score >= 75) return '#10b981'; // Green
    if (score >= 40) return '#f59e0b'; // Amber
    return '#ef4444'; // Red
  };

  // Stacked chart calculation
  const breakdownChartData = useMemo(() => {
    if (!scoreData?.breakdown) return [];
    return [{
      name: 'Breakdown',
      CRITICAL: scoreData.breakdown.CRITICAL || 0,
      HIGH: scoreData.breakdown.HIGH || 0,
      MEDIUM: scoreData.breakdown.MEDIUM || 0,
      LOW: scoreData.breakdown.LOW || 0
    }];
  }, [scoreData]);

  // Evolve engine contributions statistics
  const engineStats = useMemo(() => {
    let secrets = 0;
    let semgrep = 0;
    let codeql = 0;
    let trivy = 0;
    let history = 0;
    
    findings.forEach(f => {
      const scanners = f.supporting_scanners || [f.scanner];
      scanners.forEach((sc: string) => {
        const name = String(sc).toLowerCase();
        if (name === 'pattern' || name === 'entropy' || name === 'secrets') {
          secrets += 1;
        } else if (name === 'semgrep') {
          semgrep += 1;
        } else if (name === 'codeql') {
          codeql += 1;
        } else if (name === 'trivy') {
          trivy += 1;
        } else if (name === 'history') {
          history += 1;
        }
      });
    });
    
    return { secrets, semgrep, codeql, trivy, history };
  }, [findings]);

  // Filtering findings
  const filteredFindings = useMemo(() => {
    let result = [...findings];

    // Filter by source type
    if (sourceFilter !== 'all') {
      if (sourceFilter === 'secrets') {
        result = result.filter(f => f.source_type === 'pattern' || f.source_type === 'entropy');
      } else {
        result = result.filter(f => f.source_type === sourceFilter);
      }
    }

    // Filter by severity
    if (severityFilter !== 'all') {
      result = result.filter(f => f.severity.toUpperCase() === severityFilter.toUpperCase());
    }

    // Sorting
    const severityMap: Record<string, number> = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    result.sort((a, b) => {
      if (sortBy === 'severity') {
        const valA = severityMap[a.severity.toUpperCase()] || 0;
        const valB = severityMap[b.severity.toUpperCase()] || 0;
        return valB - valA; // High severity first
      } else {
        return (b.exposure_days || 0) - (a.exposure_days || 0); // Most exposure days first
      }
    });

    return result;
  }, [findings, sourceFilter, severityFilter, sortBy]);

  // Group findings by secret_hash + secret_type to collapse duplicate leaks
  const groupedFindings = useMemo(() => {
    const groups: Record<string, any> = {};

    for (const f of filteredFindings) {
      const key = `${f.secret_hash}-${f.secret_type}`;
      if (!groups[key]) {
        groups[key] = {
          ...f,
          occurrences: f.occurrences && f.occurrences.length > 0 ? f.occurrences : [{
            file_path: f.file_path,
            line_number: f.line_number,
            found_in: f.found_in,
            commit_hash: f.commit_hash
          }]
        };
      }
    }

    return Object.values(groups);
  }, [filteredFindings]);

  // Check if there's any cross-repo cluster leaks warning
  const clusterLeakCount = useMemo(() => {
    return dataset?.clusters?.length ?? 0;
  }, [dataset]);

  if (isLoading) {
    return (
      <div className="flex h-96 flex-col items-center justify-center gap-3">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-slate-800 border-t-accent-blue" />
        <span className="text-sm font-medium text-slate-400">Loading analysis reports...</span>
      </div>
    );
  }

  if (isError || !repo) {
    return (
      <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-6 text-center text-red-400">
        <p className="font-semibold">Repository analysis profile not found.</p>
        <button 
          onClick={() => router.push('/')}
          className="mt-3 inline-flex items-center gap-1 text-sm font-medium underline hover:text-red-300"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* 1. Page Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between border-b border-border-dark pb-6">
        <div className="space-y-1">
          <button 
            onClick={() => router.push('/')}
            className="group inline-flex items-center gap-1 text-xs font-semibold uppercase tracking-wider text-slate-500 hover:text-white transition-colors"
          >
            <ArrowLeft className="h-3 w-3 group-hover:-translate-x-0.5 transition-transform" />
            Back to Dashboard
          </button>
          
          <div className="flex flex-wrap items-center gap-3 mt-2">
            <h1 className="text-2xl font-extrabold text-white font-mono">{repo.owner}/{repo.name}</h1>
            <a 
              href={repo.github_url} 
              target="_blank" 
              rel="noreferrer" 
              className="text-slate-500 hover:text-white transition-colors"
            >
              <ExternalLink className="h-4.5 w-4.5" />
            </a>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleScan}
            disabled={isScanning || repo.status === 'scanning'}
            className="inline-flex items-center gap-2 rounded-lg bg-accent-blue hover:bg-accent-blue-hover disabled:opacity-50 px-4 py-2 text-sm font-semibold text-white transition-colors cursor-pointer"
          >
            <Play className="h-4 w-4" />
            <span>{repo.status === 'scanning' || isScanning ? 'Scan in Progress' : 'Run Scan'}</span>
          </button>
        </div>
      </div>

      {/* Synchronous Scan Cosmetic Stepper */}
      {(isScanning || repo.status === 'scanning') && (
        <div className="rounded-xl border border-blue-900/30 bg-blue-950/10 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-blue-400 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-blue-400 animate-ping" />
              Executing Engine Stack...
            </span>
            <span className="text-xs text-slate-500">Simulated engine timeline</span>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div 
              className="bg-accent-blue h-full transition-all duration-300"
              style={{ width: `${((scanStepIndex + 1) / SCAN_STEPS.length) * 100}%` }}
            />
          </div>

          {/* Stepper list */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 pt-2">
            {SCAN_STEPS.map((step, idx) => {
              const isCompleted = idx < scanStepIndex;
              const isCurrent = idx === scanStepIndex;
              return (
                <div 
                  key={step.label} 
                  className={`flex items-center gap-2 rounded-lg p-2.5 border text-xs ${
                    isCompleted ? 'border-emerald-500/10 bg-emerald-950/10 text-emerald-400' :
                    isCurrent ? 'border-blue-500/20 bg-blue-950/20 text-blue-400' :
                    'border-border-dark bg-panel/30 text-slate-500'
                  }`}
                >
                  {isCompleted ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                  ) : isCurrent ? (
                    <Clock className="h-4 w-4 shrink-0 text-blue-400 animate-spin" />
                  ) : (
                    <div className="h-4 w-4 shrink-0 rounded-full border border-slate-700 bg-slate-900" />
                  )}
                  <span className="truncate">{step.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {scanError && (
        <div className="rounded-xl border border-red-500/20 bg-red-950/15 p-4 text-sm text-red-400">
          <h4 className="font-bold flex items-center gap-1.5"><AlertTriangle className="h-4 w-4" /> Scan Failed</h4>
          <p className="mt-1">{scanError}</p>
        </div>
      )}

      {repo.status === 'done' && (
        <>
          {/* 2. Stats and Score breakdown row */}
          <div className="grid grid-cols-1 gap-6 md:grid-cols-12">
            
            {/* Pie/Semicircle Score Gauge */}
            <div className="md:col-span-4 rounded-xl border border-border-dark bg-panel p-6 flex flex-col items-center justify-between text-center min-h-[260px]">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 self-start">Security Rating</h3>
              
              <div className="relative w-48 h-28 mt-2 flex justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
                    <Pie
                      data={gaugeData}
                      cx="50%"
                      cy="100%"
                      startAngle={180}
                      endAngle={0}
                      innerRadius={55}
                      outerRadius={75}
                      paddingAngle={0}
                      dataKey="value"
                    >
                      <Cell fill={getGaugeColor(scoreData?.security_score ?? 100)} />
                      <Cell fill="#1e293b" />
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute bottom-0 flex flex-col items-center">
                  <span className="text-3xl font-extrabold text-white">
                    {scoreData?.security_score ?? 100}
                  </span>
                  <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mt-0.5">SCORE</span>
                </div>
              </div>

              <div className="w-full mt-4 text-xs font-semibold uppercase text-slate-400">
                {scoreData?.security_score && scoreData.security_score >= 75 ? (
                  <span className="text-emerald-400">Rating: Satisfactory</span>
                ) : scoreData?.security_score && scoreData.security_score >= 40 ? (
                  <span className="text-amber-400">Rating: Moderate Warning</span>
                ) : (
                  <span className="text-red-400">Rating: Critical Danger</span>
                )}
              </div>
            </div>

            {/* Metrics Breakdown Bar Chart */}
            <div className="md:col-span-8 rounded-xl border border-border-dark bg-panel p-6 flex flex-col justify-between min-h-[260px]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Severity Breakdown (Validated)</h3>
                <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
                  <span>Raw: <strong className="text-slate-300 font-mono">{dataset?.raw_count ?? 0}</strong></span>
                  <span>Validated: <strong className="text-emerald-400 font-mono">{dataset?.validated_count ?? 0}</strong></span>
                  <span>Needs Review: <strong className="text-amber-400 font-mono">{dataset?.needs_review_count ?? 0}</strong></span>
                  <span>Rejected: <strong className="text-slate-400 font-mono">{dataset?.rejected_count ?? 0}</strong></span>
                </div>
              </div>

              {/* Bar Stack representation */}
              <div className="w-full h-16 mt-4">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={breakdownChartData} layout="vertical" barSize={16}>
                    <XAxis type="number" hide />
                    <YAxis type="category" dataKey="name" hide />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#111622', borderColor: '#1e293b', color: '#f8fafc' }}
                      itemStyle={{ color: '#f8fafc' }}
                    />
                    <Bar dataKey="CRITICAL" stackId="a" fill="#f87171" name="Critical" />
                    <Bar dataKey="HIGH" stackId="a" fill="#fb923c" name="High" />
                    <Bar dataKey="MEDIUM" stackId="a" fill="#facc15" name="Medium" />
                    <Bar dataKey="LOW" stackId="a" fill="#94a3b8" name="Low" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* 4 Cards Count Chips */}
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 mt-2">
                <div className="rounded-lg border border-red-500/20 bg-red-950/10 p-3 text-center">
                  <span className="text-[10px] uppercase font-bold text-red-400/80">Critical</span>
                  <p className="text-xl font-bold text-red-400 mt-1">{scoreData?.breakdown?.CRITICAL || 0}</p>
                </div>
                <div className="rounded-lg border border-orange-500/20 bg-orange-950/10 p-3 text-center">
                  <span className="text-[10px] uppercase font-bold text-orange-400/80">High</span>
                  <p className="text-xl font-bold text-orange-400 mt-1">{scoreData?.breakdown?.HIGH || 0}</p>
                </div>
                <div className="rounded-lg border border-yellow-500/20 bg-yellow-950/10 p-3 text-center">
                  <span className="text-[10px] uppercase font-bold text-yellow-400/80">Medium</span>
                  <p className="text-xl font-bold text-yellow-400 mt-1">{scoreData?.breakdown?.MEDIUM || 0}</p>
                </div>
                <div className="rounded-lg border border-slate-500/20 bg-slate-950/10 p-3 text-center">
                  <span className="text-[10px] uppercase font-bold text-slate-400/80">Low</span>
                  <p className="text-xl font-bold text-slate-300 mt-1">{scoreData?.breakdown?.LOW || 0}</p>
                </div>
              </div>
            </div>

          </div>

          {/* Validation Details & Root Causes */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {/* Confidence Distribution */}
            <div className="rounded-xl border border-border-dark bg-panel p-6 space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Confidence Distribution</h3>
              <div className="space-y-3.5">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-emerald-400 font-semibold">Validated (High)</span>
                    <span className="text-slate-300 font-mono">{dataset?.validated_count ?? 0}</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-emerald-500 h-full" style={{ width: `${dataset?.raw_count ? ((dataset.validated_count / dataset.raw_count) * 100) : 0}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-amber-400 font-semibold">Needs Review (Medium)</span>
                    <span className="text-slate-300 font-mono">{dataset?.needs_review_count ?? 0}</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-amber-500 h-full" style={{ width: `${dataset?.raw_count ? ((dataset.needs_review_count / dataset.raw_count) * 100) : 0}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400 font-semibold">Rejected (Low / Ignored)</span>
                    <span className="text-slate-300 font-mono">{dataset?.rejected_count ?? 0}</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-slate-600 h-full" style={{ width: `${dataset?.raw_count ? ((dataset.rejected_count / dataset.raw_count) * 100) : 0}%` }} />
                  </div>
                </div>
              </div>
            </div>

            {/* Engine Contributions */}
            <div className="rounded-xl border border-border-dark bg-panel p-6 space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Engine Contributions</h3>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between border-b border-border-dark/30 pb-1">
                  <span className="text-slate-400">Secret Engine:</span>
                  <strong className="text-white font-mono">{engineStats.secrets}</strong>
                </div>
                <div className="flex justify-between border-b border-border-dark/30 pb-1">
                  <span className="text-slate-400">Semgrep:</span>
                  <strong className="text-white font-mono">{engineStats.semgrep}</strong>
                </div>
                <div className="flex justify-between border-b border-border-dark/30 pb-1">
                  <span className="text-slate-400">CodeQL:</span>
                  <strong className="text-white font-mono">{engineStats.codeql}</strong>
                </div>
                <div className="flex justify-between border-b border-border-dark/30 pb-1">
                  <span className="text-slate-400">Trivy:</span>
                  <strong className="text-white font-mono">{engineStats.trivy}</strong>
                </div>
                <div className="flex justify-between border-b border-border-dark/30 pb-1">
                  <span className="text-slate-400">Git History:</span>
                  <strong className="text-white font-mono">{engineStats.history}</strong>
                </div>
                <div className="flex justify-between pt-1 border-t border-slate-700/60 font-semibold">
                  <span className="text-slate-300">Merged Findings:</span>
                  <strong className="text-emerald-400 font-mono">{findings.length}</strong>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-300">Raw Findings:</span>
                  <strong className="text-slate-400 font-mono">{dataset?.raw_count ?? 0}</strong>
                </div>
              </div>
            </div>

            {/* Root Cause Clusters */}
            <div className="md:col-span-2 rounded-xl border border-border-dark bg-panel p-6 space-y-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Root Cause Analysis</h3>
              {dataset?.clusters && dataset.clusters.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {dataset.clusters.map((c: any) => (
                    <div key={c.root_cause} className="border border-border-dark/60 bg-panel-dark/45 rounded-lg p-3.5 space-y-1">
                      <div className="flex justify-between items-start">
                        <h4 className="text-xs font-bold text-white leading-tight">{c.root_cause}</h4>
                        <span className="text-[10px] font-bold uppercase bg-blue-900/35 text-blue-400 px-1.5 py-0.5 rounded font-mono shrink-0">
                          {c.findings_count} {c.findings_count === 1 ? 'type' : 'types'}
                        </span>
                      </div>
                      <div className="flex gap-3 text-[11px] text-slate-400 pt-1 font-sans">
                        <span>Occurrences: <strong className="text-slate-300 font-mono">{c.occurrences_count}</strong></span>
                        <span>Affected Files: <strong className="text-slate-300 font-mono">{c.affected_files_count}</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-slate-500 text-xs text-center py-6">No validated root causes identified.</div>
              )}
            </div>
          </div>

          {/* 3. AI Risk Summary Card */}
          {repo.ai_reasoning && (
            <div className="rounded-xl border border-border-dark bg-panel p-6 space-y-3 shadow-lg">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Cpu className="h-4.5 w-4.5 text-accent-blue" />
                AI Risk Assessment (Groq/Llama-3.3)
              </h3>
              <div className="max-w-4xl">
                <MarkdownRenderer content={repo.ai_reasoning} />
              </div>
            </div>
          )}

          {/* 4. OWASP Context Callout */}
          <div className="rounded-xl border border-border-dark bg-panel/30 overflow-hidden shadow-sm">
            <button
              onClick={() => setIsOwaspCollapsed(!isOwaspCollapsed)}
              className="w-full flex items-center justify-between px-6 py-4 text-left hover:bg-slate-800/20 transition-colors"
            >
              <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Info className="h-4.5 w-4.5 text-slate-400" />
                OWASP Compliance Framework
              </span>
              {isOwaspCollapsed ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronUp className="h-4 w-4 text-slate-400" />}
            </button>
            
            {!isOwaspCollapsed && (
              <div className="px-6 pb-6 pt-2 border-t border-border-dark/30 text-xs text-slate-400 space-y-2 leading-relaxed">
                <p>
                  Findings are categorized against the <strong className="text-slate-300">OWASP Top 10 (2021)</strong> framework. Examples of scanned items include:
                </p>
                <ul className="list-disc list-inside space-y-1 text-slate-400/90 pl-1">
                  <li><strong className="text-slate-300">A01:2021-Broken Access Control</strong> (e.g. hardcoded secrets and authentication tokens)</li>
                  <li><strong className="text-slate-300">A02:2021-Cryptographic Failures</strong> (e.g. usage of insecure hash functions MD5/SHA1, weak key generation)</li>
                  <li><strong className="text-slate-300">A05:2021-Security Misconfiguration</strong> (e.g. react dangerouslySetInnerHTML usage)</li>
                  <li><strong className="text-slate-300">A06:2021-Vulnerable and Outdated Components</strong> (e.g. outdated dependency packages flagged by Trivy scans)</li>
                </ul>
              </div>
            )}
          </div>

          {/* 5. Signed Report Panel (Interactive Cryptography Demo) */}
          {reportSignature && (
            <div className="rounded-xl border border-border-dark bg-panel overflow-hidden shadow-lg">
              <div className="flex items-center justify-between px-6 py-4 border-b border-border-dark bg-panel/40">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Terminal className="h-4.5 w-4.5 text-accent-blue" />
                  RSA-Signed Scan Report (Cryptographic Payload)
                </h3>
                <button
                  onClick={() => setIsReportCollapsed(!isReportCollapsed)}
                  className="text-slate-400 hover:text-white"
                >
                  {isReportCollapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
                </button>
              </div>

              {!isReportCollapsed && (
                <div className="p-6 space-y-4">
                  <p className="text-xs text-slate-400">
                    The backend signs this JSON structure. Any single character edit (e.g. modifying <code className="text-white bg-slate-800 px-1 py-0.5 rounded">critical_findings</code>) triggers signature validation failure to showcase tamper detection.
                  </p>

                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                    {/* JSON editor input */}
                    <div className="space-y-2">
                      <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        Payload Payload (JSON format)
                      </label>
                      <textarea
                        value={reportText}
                        onChange={(e) => {
                          setReportText(e.target.value);
                          setVerifyResult('idle');
                        }}
                        className="w-full h-48 rounded bg-background border border-border-dark p-3 font-mono text-xs text-white focus:border-accent-blue focus:outline-none"
                      />
                    </div>

                    {/* Signature and Verification details */}
                    <div className="space-y-4 flex flex-col justify-between">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-400">
                            Report Signature (Hex Representation)
                          </label>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(reportSignature);
                              setCopiedSig(true);
                              setTimeout(() => setCopiedSig(false), 2000);
                            }}
                            className="text-slate-500 hover:text-white"
                            title="Copy signature"
                          >
                            {copiedSig ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                          </button>
                        </div>
                        <div className="w-full bg-background border border-border-dark rounded p-3 font-mono text-[10px] text-slate-500 break-all select-all leading-normal">
                          {reportSignature}
                        </div>
                      </div>

                      {/* Verify controls */}
                      <div className="flex items-center gap-4">
                        <button
                          onClick={handleVerify}
                          disabled={isVerifying}
                          className="rounded bg-accent-blue hover:bg-accent-blue-hover text-white text-xs font-semibold px-4 py-2.5 transition-colors cursor-pointer"
                        >
                          Verify Signature
                        </button>
                        
                        <button
                          onClick={async () => {
                            try {
                              const signed = await api.getSignedReport(id);
                              if (signed?.report && signed?.signature) {
                                setReportText(JSON.stringify(signed.report, null, 2));
                                setReportSignature(signed.signature);
                                setSignedReportLoaded(true);
                                setVerifyResult('idle');
                                return;
                              }
                            } catch (err) {
                              console.warn('Reset payload fell back to current in-memory report', err);
                            }

                            setVerifyResult('idle');
                          }}
                          className="rounded border border-slate-700 bg-slate-800/40 text-slate-300 hover:text-white text-xs font-semibold px-4 py-2.5 transition-colors cursor-pointer"
                        >
                          Reset Payload
                        </button>

                        <div className="flex-1 flex items-center justify-end">
                          {verifyResult === 'valid' && (
                            <span className="inline-flex items-center gap-1 text-emerald-400 font-bold text-xs uppercase tracking-wider bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded">
                              <ShieldCheck className="h-4 w-4" /> Integrity Secure
                            </span>
                          )}
                          {verifyResult === 'invalid' && (
                            <span className="inline-flex items-center gap-1 text-red-400 font-bold text-xs uppercase tracking-wider bg-red-500/10 border border-red-500/20 px-3 py-1.5 rounded">
                              <ShieldAlert className="h-4 w-4 animate-pulse" /> Tamper Detected
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 6. Findings Table */}
          <div className="space-y-4">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-xl font-bold text-white">Scanned Findings ({groupedFindings.length} unique, {filteredFindings.length} total)</h2>
              
              {/* Filter controls */}
              <div className="flex flex-wrap items-center gap-3">
                {/* Engine Source Filter */}
                <select
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value as any)}
                  className="rounded-lg border border-border-dark bg-panel py-1.5 px-3 text-xs text-white focus:border-accent-blue focus:outline-none"
                >
                  <option value="all">All Engines</option>
                  <option value="secrets">Secret Scanner</option>
                  <option value="semgrep">Static Analysis (Semgrep)</option>
                  <option value="trivy">Dependencies (Trivy)</option>
                  <option value="codeql">Semantic Analysis (CodeQL)</option>
                </select>

                {/* Severity Filter */}
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value as any)}
                  className="rounded-lg border border-border-dark bg-panel py-1.5 px-3 text-xs text-white focus:border-accent-blue focus:outline-none"
                >
                  <option value="all">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>

                {/* Sort Filter */}
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as any)}
                  className="rounded-lg border border-border-dark bg-panel py-1.5 px-3 text-xs text-white focus:border-accent-blue focus:outline-none"
                >
                  <option value="severity">Sort: Severity</option>
                  <option value="exposure">Sort: Exposure Duration</option>
                </select>
              </div>
            </div>

            {/* Clusters warning if overlapping leaks */}
            {clusterLeakCount > 0 && (
              <div 
                onClick={() => router.push('/clusters')}
                className="flex items-center justify-between rounded-lg border border-yellow-500/10 bg-yellow-950/10 px-4 py-3 text-xs text-yellow-500 cursor-pointer hover:bg-yellow-950/15 transition-all"
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  <span>
                    <strong>{clusterLeakCount} secret(s)</strong> in this repository also appear in other monitored repositories.
                  </span>
                </div>
                <span className="underline font-semibold flex items-center gap-0.5">
                  View Clusters &rarr;
                </span>
              </div>
            )}

            {filteredFindings.length === 0 ? (
              <div className="rounded-xl border border-border-dark bg-panel/30 py-12 text-center text-slate-500 text-sm">
                No findings match the selected filters.
              </div>
            ) : (
              <div className="overflow-hidden rounded-xl border border-border-dark bg-panel shadow-lg">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-border-dark bg-panel/50 text-xs font-semibold uppercase tracking-wider text-slate-400">
                      <th className="w-8"></th>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Confirmed By</th>
                      <th className="py-3 px-4">File Location</th>
                      <th className="py-3 px-4">Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-dark/60 text-sm text-slate-300">
                    {groupedFindings.map((finding, idx) => {
                      const rowKey = finding.secret_hash;
                      const isExpanded = !!expandedFindings[rowKey];
                      
                      const getSeverityColor = (sev: string) => {
                        switch (sev.toUpperCase()) {
                          case 'CRITICAL': return 'text-red-400 bg-red-500/10 border-red-500/20';
                          case 'HIGH': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
                          case 'MEDIUM': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
                          case 'LOW':
                          default: return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
                        }
                      };

                      const getEngineLabel = (src: string) => {
                        switch (src) {
                          case 'pattern':
                          case 'entropy':
                            return 'Secret Scanner';
                          case 'semgrep':
                            return 'Semgrep';
                          case 'trivy':
                            return 'Trivy SCA';
                          default:
                            return src;
                        }
                      };

                      return (
                        <React.Fragment key={rowKey}>
                          {/* Row */}
                          <tr 
                            onClick={() => toggleExpandFinding(rowKey)}
                            className="transition-colors hover:bg-slate-800/20 cursor-pointer"
                          >
                            <td className="py-3.5 pl-3">
                              {isExpanded ? (
                                <ChevronUp className="h-4 w-4 text-slate-500" />
                              ) : (
                                <ChevronDown className="h-4 w-4 text-slate-500" />
                              )}
                            </td>
                            <td className="py-3.5 px-4">
                              <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-bold ${getSeverityColor(finding.severity)}`}>
                                {finding.severity}
                              </span>
                            </td>
                            <td className="py-3.5 px-4 font-mono text-xs font-bold text-white truncate max-w-[150px]">
                              {finding.secret_type || finding.rule_id}
                            </td>
                            <td className="py-3.5 px-4 text-xs font-semibold text-slate-400">
                              <div className="flex flex-wrap gap-1">
                                {(finding.supporting_scanners || [finding.source_type]).map((sc: string) => {
                                  const name = sc === 'pattern' || sc === 'entropy' || sc === 'secrets' ? 'Secrets' :
                                               sc === 'semgrep' ? 'Semgrep' :
                                               sc === 'trivy' ? 'Trivy' :
                                               sc === 'codeql' ? 'CodeQL' : sc;
                                  return (
                                    <span key={sc} className="inline-flex items-center gap-0.5 rounded-full bg-slate-900 border border-slate-700/60 px-2 py-0.5 text-[10px] font-medium text-slate-300">
                                      <span className="text-emerald-400 font-bold font-mono mr-0.5">✓</span> {name}
                                    </span>
                                  );
                                })}
                              </div>
                            </td>
                            <td className="py-3.5 px-4 font-mono text-xs text-slate-400 max-w-[250px] truncate" title={`${finding.file_path}:${finding.line_range || finding.line_number}`}>
                              {finding.file_path}:{finding.line_range || finding.line_number}
                              {finding.occurrences.length > 1 && (
                                <span className="ml-2 inline-flex items-center rounded-full bg-slate-800 text-[10px] font-semibold text-slate-300 border border-slate-700 px-1.5 py-0.5">
                                  + {finding.occurrences.length - 1} more
                                </span>
                              )}
                            </td>
                            <td className="py-3.5 px-4">
                              <span className="font-mono text-xs text-slate-300 font-bold bg-slate-800/40 border border-slate-700/60 px-1.5 py-0.5 rounded">
                                {finding.exposure_score}
                              </span>
                            </td>
                          </tr>

                          {/* Expanded Details */}
                          {isExpanded && (
                            <tr className="bg-slate-900/40">
                              <td colSpan={6} className="py-5 px-6 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                  {/* Left details */}
                                  <div className="space-y-4">
                                    {finding.status && (
                                      <div>
                                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Validation Status</span>
                                        <div className="flex items-center gap-2 mt-1">
                                          <span className={`inline-flex rounded text-[10px] font-bold px-2 py-0.5 ${
                                            finding.status === 'VALIDATED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                          }`}>
                                            {finding.status}
                                          </span>
                                          <span className="text-xs text-slate-400 font-sans">
                                            Confidence Score: <strong className="text-slate-200 font-mono">{finding.confidence}/100</strong>
                                          </span>
                                        </div>
                                      </div>
                                    )}

                                    {finding.engines && finding.engines.length > 0 && (
                                      <div className="space-y-2">
                                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Detection Engines</span>
                                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                                          {finding.engines.map((eng: any, eIdx: number) => (
                                            <div key={eIdx} className="bg-slate-950/60 rounded border border-border-dark/40 p-2.5 text-xs">
                                              <div className="flex items-center justify-between">
                                                <span className="font-semibold text-white flex items-center gap-1">
                                                  <span className="text-emerald-400 font-bold font-mono">✓</span> {eng.name}
                                                </span>
                                                <span className="text-[9px] font-bold text-slate-400 uppercase tracking-wider bg-slate-900 border border-slate-700/60 px-1 py-0.5 rounded">
                                                  {eng.severity}
                                                </span>
                                              </div>
                                              <p className="text-slate-400 text-[10px] mt-0.5">{eng.type}</p>
                                              <p className="font-mono text-[9px] text-slate-500 mt-1 truncate" title={eng.rule}>Rule: {eng.rule}</p>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {finding.owasp_category && (
                                      <div>
                                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">OWASP Top 10 Category</span>
                                        <span className="inline-flex rounded bg-accent-blue/10 border border-accent-blue/20 text-accent-blue text-xs font-bold px-2 py-0.5 mt-1">
                                          {finding.owasp_category}
                                        </span>
                                      </div>
                                    )}

                                    {/* Scan Locations list */}
                                    <div>
                                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Scan Locations ({finding.occurrences.length})</span>
                                      <ul className="mt-1.5 space-y-1.5 max-h-36 overflow-y-auto pr-2">
                                        {finding.occurrences.map((occ: any, oIdx: number) => (
                                          <li key={occ.id || oIdx} className="text-xs font-mono flex items-center justify-between bg-slate-950 px-2 py-1.5 rounded border border-border-dark/40">
                                            <span className="text-slate-300 truncate max-w-[280px]" title={occ.file_path}>
                                              {occ.file_path}:{occ.line_number}
                                            </span>
                                            {occ.found_in === 'history' ? (
                                              <span className="text-[9px] font-bold text-violet-400 bg-violet-500/10 border border-violet-500/25 rounded px-1.5 py-0.5" title={occ.commit_hash}>
                                                history ({occ.commit_hash?.slice(0, 7)})
                                              </span>
                                            ) : (
                                              <span className="text-[9px] font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 rounded px-1.5 py-0.5">
                                                active
                                              </span>
                                            )}
                                          </li>
                                        ))}
                                      </ul>
                                    </div>

                                    {finding.found_in === 'history' && (
                                      <div>
                                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Commit Lifecycle</span>
                                        <span className="inline-flex rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs font-bold px-2 py-0.5 mt-1">
                                          Found in git history (Inactive in HEAD)
                                        </span>
                                      </div>
                                    )}

                                    {finding.exposure_days !== undefined && (
                                      <div>
                                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Leak Exposure Duration</span>
                                        <p className="text-xs text-slate-300 mt-1">
                                          Exposed for <strong className="text-white font-mono">{finding.exposure_days} days</strong> (Calculated score: <strong className="text-white font-mono">{finding.exposure_score}</strong>)
                                        </p>
                                      </div>
                                    )}

                                    {finding.vulnerability_description && (
                                      <div>
                                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Vulnerability Description</span>
                                        <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                                          {finding.vulnerability_description}
                                        </p>
                                      </div>
                                    )}

                                    {finding.recommendation && (
                                      <div className="bg-slate-800/40 rounded p-3 border border-slate-700/40">
                                        <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider block">Remediation Action</span>
                                        <p className="text-xs text-slate-300 mt-1 leading-relaxed font-sans">
                                          {finding.recommendation}
                                        </p>
                                      </div>
                                    )}
                                  </div>

                                  {/* Code snippet / suggestion */}
                                  <div className="space-y-3">
                                    <div>
                                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Evidence Snippet</span>
                                      <pre className="w-full bg-slate-950 border border-border-dark rounded-lg p-3 font-mono text-[11px] text-slate-300 mt-1 leading-relaxed overflow-x-auto">
                                        {finding.snippet}
                                      </pre>
                                    </div>

                                    {finding.code_flow && finding.code_flow.length > 0 && (
                                      <div className="rounded-lg border border-accent-blue/15 bg-slate-950 p-4 space-y-3">
                                        <span className="text-[10px] font-bold text-accent-blue uppercase tracking-wider block">
                                          Semantic Data-Flow Path (CodeQL)
                                        </span>
                                        <div className="relative pl-5 border-l-2 border-slate-800 space-y-4">
                                          {finding.code_flow.map((step: any, sIdx: number) => {
                                            const isSource = sIdx === 0;
                                            const isSink = sIdx === finding.code_flow.length - 1;
                                            return (
                                              <div key={sIdx} className="relative">
                                                {/* Bullet dot */}
                                                <span className={`absolute -left-[25px] top-1 h-2.5 w-2.5 rounded-full border ${
                                                  isSource ? 'bg-blue-400 border-blue-400 shadow-[0_0_8px_rgba(96,165,250,0.5)]' :
                                                  isSink ? 'bg-red-400 border-red-400 shadow-[0_0_8px_rgba(248,113,113,0.5)] animate-pulse' :
                                                  'bg-slate-700 border-slate-600'
                                                }`} />
                                                <div className="space-y-0.5">
                                                  <div className="flex items-center gap-2">
                                                    <span className="text-xs font-semibold text-white">{step.label}</span>
                                                    <span className="text-[10px] font-mono text-slate-500">{step.file}:{step.line}</span>
                                                  </div>
                                                </div>
                                              </div>
                                            );
                                          })}
                                        </div>
                                      </div>
                                    )}

                                    {finding.ai_suggested_fix && (
                                      <div className="rounded-lg border border-accent-blue/20 bg-accent-blue/5 p-3 space-y-1">
                                        <span className="inline-flex items-center gap-1 rounded bg-accent-blue/20 text-accent-blue text-[9px] font-bold px-1.5 py-0.5 uppercase tracking-wider">
                                          AI Remediation Recommendation (Llama)
                                        </span>
                                        <pre className="w-full bg-slate-950 border border-border-dark/60 rounded p-2.5 font-mono text-[10px] text-slate-300 overflow-x-auto leading-relaxed select-all">
                                          {finding.ai_suggested_fix}
                                        </pre>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {/* Empty State: Repo has not been scanned yet */}
      {repo.status === 'pending' && (
        <div className="rounded-2xl border border-dashed border-border-dark bg-panel/30 py-16 text-center max-w-3xl mx-auto">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-slate-900 border border-border-dark text-slate-400">
            <Database className="h-6 w-6" />
          </div>
          <h3 className="mt-4 text-lg font-bold text-white">Repository registered successfully</h3>
          <p className="mx-auto mt-2 max-w-sm text-sm text-slate-400">
            Trigger a static security scan to examine this repository for vulnerability risks, dependency mismatches, and exposed passwords.
          </p>
          <button
            onClick={handleScan}
            disabled={isScanning}
            className="mt-5 inline-flex items-center gap-2 rounded-lg bg-accent-blue px-5 py-2.5 text-sm font-semibold text-white hover:bg-accent-blue-hover transition-colors cursor-pointer"
          >
            <Play className="h-4 w-4" />
            <span>Start Security Scan</span>
          </button>
        </div>
      )}

      {/* 7. Danger Zone */}
      <div className="rounded-xl border border-red-500/20 bg-red-950/5 p-6 space-y-4">
        <h3 className="text-sm font-bold text-red-400 uppercase tracking-wider">Danger Zone</h3>
        <p className="text-xs text-slate-400">
          Removing this repository deletes all scanned files, cached findings, exposure metrics, and cryptographic reports associated with it from the database. This action is irreversible.
        </p>
        <button
          onClick={handleDelete}
          className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-950/20 px-3 py-1.5 text-xs font-semibold text-red-400 hover:bg-red-950/35 transition-colors cursor-pointer"
        >
          <Trash2 className="h-3.5 w-3.5" />
          <span>Remove Repository profile</span>
        </button>
      </div>
    </div>
  );
}

function parseBolds(text: string): React.ReactNode[] {
  const parts = text.split(/\*\*([^*]+)\*\*/g);
  return parts.map((part, i) => {
    if (i % 2 === 1) {
      return <strong key={i} className="font-semibold text-white">{part}</strong>;
    }
    return <span key={i}>{part}</span>;
  });
}

function MarkdownRenderer({ content }: { content: string }) {
  if (!content) return null;

  const lines = content.split('\n');

  return (
    <div className="space-y-4">
      {lines.map((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed) return <div key={idx} className="h-2" />;

        if (trimmed.startsWith('###')) {
          const text = trimmed.replace(/^###\s*/, '');
          return <h4 key={idx} className="text-sm font-bold text-white mt-4 border-b border-border-dark pb-1">{parseBolds(text)}</h4>;
        }
        if (trimmed.startsWith('##')) {
          const text = trimmed.replace(/^##\s*/, '');
          return <h3 key={idx} className="text-base font-extrabold text-white mt-5">{parseBolds(text)}</h3>;
        }
        if (trimmed.startsWith('#')) {
          const text = trimmed.replace(/^#\s*/, '');
          return <h2 key={idx} className="text-lg font-black text-white mt-6">{parseBolds(text)}</h2>;
        }

        if (trimmed.startsWith('-') || trimmed.startsWith('*')) {
          const text = trimmed.replace(/^[-*]\s*/, '');
          return (
            <div key={idx} className="flex items-start gap-2 text-sm text-slate-300 pl-4">
              <span className="text-accent-blue mt-1.5 h-1.5 w-1.5 rounded-full bg-accent-blue shrink-0" />
              <span>{parseBolds(text)}</span>
            </div>
          );
        }

        const numberedHeaderMatch = trimmed.match(/^(\d+)\.\s+\*\*(.+?)\*\*(.*)$/);
        if (numberedHeaderMatch) {
          const num = numberedHeaderMatch[1];
          const title = numberedHeaderMatch[2];
          const rest = numberedHeaderMatch[3];
          return (
            <div key={idx} className="space-y-2 mt-6">
              <h3 className="text-sm font-bold text-white flex items-center gap-2 border-b border-border-dark/60 pb-1.5 uppercase tracking-wider text-accent-blue">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-accent-blue/10 text-[10px] text-accent-blue border border-accent-blue/20">{num}</span>
                {title}
              </h3>
              {rest.trim() && (
                <p className="text-sm text-slate-300 leading-relaxed pl-7">{parseBolds(rest.trim())}</p>
              )}
            </div>
          );
        }

        return <p key={idx} className="text-sm text-slate-300 leading-relaxed">{parseBolds(trimmed)}</p>;
      })}
    </div>
  );
}
