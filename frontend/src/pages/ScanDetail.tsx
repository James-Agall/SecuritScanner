import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getScan, getVulnerabilities, reportUrl, type Scan, type Vulnerability } from '../api';
import { phaseLabel } from '../phaseLabels';
import StatusBadge from '../components/StatusBadge';
import VulnerabilityCard from '../components/VulnerabilityCard';

const POLL_INTERVAL_MS = 3000;
const SEVERITY_ORDER: Record<Vulnerability['severity'], number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const scanId = Number(id);

  const [scan, setScan] = useState<Scan | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [notFound, setNotFound] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const scanData = await getScan(scanId);
      setScan(scanData);
      if (scanData.status === 'completed' || scanData.status === 'running') {
        setVulns(await getVulnerabilities(scanId));
      }
    } catch {
      setNotFound(true);
    }
  }, [scanId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!scan || scan.status === 'completed' || scan.status === 'failed') return;
    const interval = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [scan, refresh]);

  if (notFound) {
    return (
      <div className="flex flex-col gap-4">
        <p className="text-sm text-red-600 dark:text-red-400">Scan {scanId} not found.</p>
        <Link to="/" className="text-sm text-slate-600 hover:underline dark:text-slate-400">
          ← Back to scans
        </Link>
      </div>
    );
  }

  if (!scan) {
    return <p className="text-sm text-slate-500">Loading…</p>;
  }

  const sortedVulns = [...vulns].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const isCompleted = scan.status === 'completed';

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link to="/" className="text-sm text-slate-500 hover:underline">
          ← Back to scans
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="break-all text-2xl font-semibold text-slate-900 dark:text-slate-100">{scan.target_url}</h1>
          <StatusBadge status={scan.status} />
        </div>
        <p className="mt-1 text-sm text-slate-500">Started {scan.start_time}</p>
      </div>

      {isCompleted ? (
        <div className="flex flex-wrap items-center gap-3">
          <a
            href={reportUrl(scan.id, 'html')}
            target="_blank"
            rel="noreferrer"
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-900"
          >
            View HTML report
          </a>
          <a
            href={reportUrl(scan.id, 'pdf')}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-900"
          >
            Download PDF
          </a>
          <span className="text-sm text-slate-500">
            {vulns.length} finding{vulns.length === 1 ? '' : 's'}
          </span>
        </div>
      ) : scan.status === 'failed' ? (
        <p className="rounded-md bg-red-50 p-3 text-sm text-red-700 dark:bg-red-950/40 dark:text-red-300">
          This scan failed. Check the API logs for details.
        </p>
      ) : (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <span className="size-2 animate-pulse rounded-full bg-blue-500" aria-hidden="true" />
          {phaseLabel(scan.current_phase)}
          {vulns.length > 0 && (
            <span>
              — {vulns.length} finding{vulns.length === 1 ? '' : 's'} so far
            </span>
          )}
        </div>
      )}

      {(isCompleted || scan.status === 'running') && (
        <div className="flex flex-col gap-3">
          {sortedVulns.length === 0
            ? isCompleted && (
                <p className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-sm text-slate-500 dark:border-slate-700">
                  No vulnerabilities found. 🎉
                </p>
              )
            : sortedVulns.map((vuln) => <VulnerabilityCard key={vuln.id} vuln={vuln} />)}
        </div>
      )}
    </div>
  );
}
