import { useCallback, useEffect, useState } from 'react';
import { deleteScan, listScans, type Scan } from '../api';
import NewScanForm from '../components/NewScanForm';
import ScanTable from '../components/ScanTable';

const POLL_INTERVAL_MS = 3000;

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setScans(await listScans());
      setError(null);
    } catch {
      setError('Could not reach the SecuritScanner API. Is it running on http://localhost:8000?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    const hasActiveScan = scans.some((s) => s.status === 'pending' || s.status === 'running');
    if (!hasActiveScan) return;
    const interval = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [scans, refresh]);

  async function handleDelete(id: number) {
    setScans((prev) => prev.filter((s) => s.id !== id));
    await deleteScan(id);
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">Scans</h1>
        <p className="text-sm text-slate-500">Crawl, probe, and report on a target's web attack surface.</p>
      </div>

      <NewScanForm onScanCreated={refresh} />

      {error && (
        <p className="rounded-md bg-red-50 p-3 text-sm text-red-700 dark:bg-red-950/40 dark:text-red-300">{error}</p>
      )}

      {loading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : (
        <ScanTable scans={scans} onDelete={handleDelete} />
      )}
    </div>
  );
}
