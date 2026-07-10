import { useState, type FormEvent } from 'react';
import { createScan, type ScanCreateRequest } from '../api';

export default function NewScanForm({ onScanCreated }: { onScanCreated: () => void }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [maxPages, setMaxPages] = useState(20);
  const [allowLocalTesting, setAllowLocalTesting] = useState(false);
  const [stealthMode, setStealthMode] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const request: ScanCreateRequest = {
        target_url: targetUrl,
        max_pages: maxPages,
        allow_local_testing: allowLocalTesting,
        stealth_mode: stealthMode,
      };
      await createScan(request);
      setTargetUrl('');
      onScanCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
    >
      <h2 className="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-300">Start a new scan</h2>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <label className="flex-1">
          <span className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Target URL</span>
          <input
            type="url"
            required
            placeholder="https://localhost:5000/"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-500 dark:border-slate-700 dark:bg-slate-950"
          />
        </label>
        <label>
          <span className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Max pages</span>
          <input
            type="number"
            min={1}
            max={200}
            value={maxPages}
            onChange={(e) => setMaxPages(Number(e.target.value))}
            className="w-24 rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-500 dark:border-slate-700 dark:bg-slate-950"
          />
        </label>
        <button
          type="submit"
          disabled={submitting}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
        >
          {submitting ? 'Starting…' : 'Start scan'}
        </button>
      </div>
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-600 dark:text-slate-400">
        <label className="flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={allowLocalTesting}
            onChange={(e) => setAllowLocalTesting(e.target.checked)}
          />
          Allow local/private-IP targets
        </label>
        <label className="flex items-center gap-1.5">
          <input type="checkbox" checked={stealthMode} onChange={(e) => setStealthMode(e.target.checked)} />
          Stealth mode
        </label>
      </div>
      {error && <p className="mt-2 text-xs text-red-600 dark:text-red-400">{error}</p>}
    </form>
  );
}
