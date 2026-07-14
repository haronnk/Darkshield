'use client';

import React, { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Copy, 
  Check, 
  RefreshCw, 
  HelpCircle, 
  Lock, 
  Terminal, 
  FileJson 
} from 'lucide-react';

export default function VerifyPage() {
  const [reportText, setReportText] = useState('');
  const [signature, setSignature] = useState('');
  const [verificationResult, setVerificationResult] = useState<'idle' | 'valid' | 'invalid' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState('');
  const [isValidating, setIsValidating] = useState(false);
  const [publicKeyPem, setPublicKeyPem] = useState('');
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedSig, setCopiedSig] = useState(false);

  // Fetch Public Key on mount
  useEffect(() => {
    async function fetchKey() {
      try {
        const res = await api.getPublicKey();
        setPublicKeyPem(res.public_key_pem);
      } catch (err) {
        console.error("Failed to load public key", err);
      }
    }
    fetchKey();
  }, []);

  const handleVerify = async () => {
    setVerificationResult('idle');
    setErrorMsg('');
    setIsValidating(true);

    let parsedReport: Record<string, any>;
    try {
      parsedReport = JSON.parse(reportText.trim());
    } catch (e: any) {
      setErrorMsg(`Invalid JSON payload format: ${e.message}`);
      setVerificationResult('invalid');
      setIsValidating(false);
      return;
    }

    if (!signature.trim()) {
      setErrorMsg('Signature string is empty');
      setVerificationResult('invalid');
      setIsValidating(false);
      return;
    }

    try {
      const res = await api.verifyReport({
        report: parsedReport,
        signature: signature.trim()
      });

      if (res.valid) {
        setVerificationResult('valid');
      } else {
        setVerificationResult('invalid');
        setErrorMsg('The signature no longer matches — this report has been altered since it was signed.');
      }
    } catch (err: any) {
      setVerificationResult('error');
      setErrorMsg(err.message || 'Internal API verification failure.');
    } finally {
      setIsValidating(false);
    }
  };

  const handleLoadSample = async () => {
    setIsValidating(true);
    setVerificationResult('idle');
    setErrorMsg('');
    try {
      const sample = await api.getSampleSignedReport();
      setReportText(JSON.stringify(sample.report, null, 2));
      setSignature(sample.signature);
      const result = await api.verifyReport({
        report: sample.report,
        signature: sample.signature,
      });
      setVerificationResult(result.valid ? 'valid' : 'invalid');
      if (!result.valid) {
        setErrorMsg('Sample report did not verify. Please refresh and try again.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Unable to load demo report.');
      setVerificationResult('error');
    } finally {
      setIsValidating(false);
    }
  };

  useEffect(() => {
    if (!reportText && !signature) {
      void handleLoadSample();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCopyKey = () => {
    navigator.clipboard.writeText(publicKeyPem);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight text-white">Cryptographic Verification Tool</h1>
        <p className="text-slate-400 mt-1">
          DarkShield scan reports are cryptographically signed with an RSA-PSS keypair. This tool verifies the payload authenticity.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
        {/* Left Form: JSON Payload and Signature */}
        <div className="lg:col-span-7 space-y-6">
          <div className="rounded-xl border border-border-dark bg-panel p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <FileJson className="h-4.5 w-4.5 text-accent-blue" />
                Report Payload (JSON)
              </h3>
              <button
                onClick={handleLoadSample}
                className="rounded border border-slate-700 bg-slate-800/40 px-2 py-1 text-xs font-semibold text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
              >
                Load & Verify Sample
              </button>
            </div>
            
            <div>
              <textarea
                value={reportText}
                onChange={(e) => setReportText(e.target.value)}
                placeholder={`{\n  "repo_id": "...",\n  "owner": "...",\n  "name": "...",\n  "total_findings": 0,\n  "critical_findings": 0,\n  "generated_at": "..."\n}`}
                className="w-full h-72 rounded-lg border border-border-dark bg-background p-4 font-mono text-xs text-white placeholder-slate-600 focus:border-accent-blue focus:outline-none focus:ring-1 focus:ring-accent-blue focus:ring-opacity-50"
              />
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
                Signature (Hex String)
              </label>
              <input
                type="text"
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
                placeholder="Paste the report_signature hex string here..."
                className="w-full rounded-lg border border-border-dark bg-background py-2.5 px-3.5 font-mono text-xs text-white placeholder-slate-600 focus:border-accent-blue focus:outline-none focus:ring-1 focus:ring-accent-blue focus:ring-opacity-50"
              />
            </div>

            <div className="pt-2">
              <button
                onClick={handleVerify}
                disabled={isValidating || !reportText || !signature}
                className="w-full rounded-lg bg-accent-blue hover:bg-accent-blue-hover py-2.5 text-sm font-semibold text-white transition-colors disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
              >
                {isValidating ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    <span>Verifying...</span>
                  </>
                ) : (
                  <span>Verify Report Integrity</span>
                )}
              </button>
            </div>
          </div>

          {/* Tamper Demonstration guide */}
          <div className="rounded-xl border border-border-dark bg-panel/30 p-5 space-y-3 text-slate-400">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Terminal className="h-4 w-4" /> How to test tamper detection:
            </h4>
            <ol className="list-decimal list-inside text-xs space-y-2 pl-1 leading-relaxed">
              <li>Navigate to <a href="/" className="text-accent-blue hover:underline">Repositories</a>, select a repo, and run a scan.</li>
              <li>Under the <strong>Signed Report</strong> panel, copy the payload JSON and the signature.</li>
              <li>Paste them here. Click <strong>Verify</strong>. You will see a green <strong className="text-emerald-400">INTEGRITY SECURE</strong> success code.</li>
              <li>Now, modify any value in the JSON payload (e.g. change <code className="font-mono bg-slate-800 px-1 py-0.5 rounded text-white">"critical_findings"</code> to <code className="font-mono bg-slate-800 px-1 py-0.5 rounded text-white">0</code>).</li>
              <li>Click <strong>Verify</strong> again. The status immediately switches to <strong className="text-red-400">TAMPER DETECTED</strong> because the cryptographic hash mismatch fails signature validation.</li>
            </ol>
          </div>
        </div>

        {/* Right Form: Results & Keys */}
        <div className="lg:col-span-5 space-y-6">
          {/* Verification Status Card */}
          <div className="rounded-xl border border-border-dark bg-panel p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">
              Verification Result
            </h3>
            
            <div className="flex flex-col items-center justify-center py-6 text-center border border-border-dark/60 rounded-lg bg-background/50">
              {verificationResult === 'idle' && (
                <div className="space-y-2">
                  <HelpCircle className="mx-auto h-12 w-12 text-slate-500" />
                  <p className="text-sm font-semibold text-slate-400">Awaiting inputs</p>
                  <p className="text-xs text-slate-500 max-w-[200px]">Provide a report payload and its signature to verify</p>
                </div>
              )}
              
              {verificationResult === 'valid' && (
                <div className="space-y-2">
                  <ShieldCheck className="mx-auto h-16 w-16 text-emerald-400 fill-emerald-500/10 animate-bounce" />
                  <p className="text-lg font-bold text-emerald-400 tracking-tight">INTEGRITY SECURE</p>
                  <p className="text-xs text-slate-400 px-4">
                    The report matches the cryptographic signature and was verified using DarkShield's public key. The payload has not been tampered with.
                  </p>
                </div>
              )}
              
              {verificationResult === 'invalid' && (
                <div className="space-y-2 px-4">
                  <ShieldAlert className="mx-auto h-16 w-16 text-red-400 fill-red-500/10" />
                  <p className="text-lg font-bold text-red-400 tracking-tight">TAMPER DETECTED</p>
                  <p className="text-xs text-red-400/90 font-medium">
                    {errorMsg || 'The payload JSON does not match the signature.'}
                  </p>
                </div>
              )}

              {verificationResult === 'error' && (
                <div className="space-y-2 px-4">
                  <ShieldAlert className="mx-auto h-16 w-16 text-yellow-500" />
                  <p className="text-base font-bold text-yellow-500">API Connection Error</p>
                  <p className="text-xs text-slate-400">
                    {errorMsg || 'Unable to complete the verification request.'}
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Public Key Display */}
          <div className="rounded-xl border border-border-dark bg-panel p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Lock className="h-4.5 w-4.5 text-accent-blue" />
                Public Key PEM
              </h3>
              {publicKeyPem && (
                <button
                  onClick={handleCopyKey}
                  className="rounded hover:bg-slate-800 p-1.5 text-slate-400 hover:text-white transition-colors"
                  title="Copy Public Key"
                >
                  {copiedKey ? (
                    <Check className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              )}
            </div>
            
            {publicKeyPem ? (
              <pre className="w-full bg-background rounded-lg p-3 text-[10px] text-slate-400 border border-border-dark overflow-x-auto font-mono max-h-56 leading-relaxed select-all">
                {publicKeyPem}
              </pre>
            ) : (
              <div className="h-24 bg-background/50 border border-border-dark/60 rounded-lg flex items-center justify-center">
                <span className="text-xs text-slate-500 animate-pulse">Fetching public key...</span>
              </div>
            )}
            
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Verify signatures independently using external utilities (e.g. OpenSSL) using RSA-PSS with SHA-256 hashing.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
