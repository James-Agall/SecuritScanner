import type { ScanStatus } from '../api';

const STYLES: Record<ScanStatus, string> = {
  pending: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  running: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  completed: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
};

export default function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${STYLES[status]}`}
    >
      {status === 'running' && (
        <span className="mr-1.5 size-1.5 animate-pulse rounded-full bg-current" aria-hidden="true" />
      )}
      {status}
    </span>
  );
}
