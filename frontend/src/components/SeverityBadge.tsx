import type { Severity } from '../api';

const STYLES: Record<Severity, string> = {
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-bold ${STYLES[severity]}`}>
      {severity}
    </span>
  );
}
