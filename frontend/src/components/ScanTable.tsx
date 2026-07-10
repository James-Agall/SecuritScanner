import { Link } from 'react-router-dom';
import type { Scan } from '../api';
import StatusBadge from './StatusBadge';

export default function ScanTable({ scans, onDelete }: { scans: Scan[]; onDelete: (id: number) => void }) {
  if (scans.length === 0) {
    return (
      <p className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-sm text-slate-500 dark:border-slate-700">
        No scans yet. Start one above.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
      <table className="w-full min-w-max text-left text-sm">
        <thead className="bg-slate-100 text-xs uppercase text-slate-600 dark:bg-slate-900 dark:text-slate-400">
          <tr>
            <th className="px-4 py-2 font-medium">Target</th>
            <th className="px-4 py-2 font-medium">Started</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Findings</th>
            <th className="px-4 py-2 font-medium"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
          {scans.map((scan) => (
            <tr key={scan.id} className="hover:bg-slate-50 dark:hover:bg-slate-900/50">
              <td className="px-4 py-2">
                <Link to={`/scans/${scan.id}`} className="font-medium text-slate-900 hover:underline dark:text-slate-100">
                  {scan.target_url}
                </Link>
              </td>
              <td className="px-4 py-2 whitespace-nowrap text-slate-600 dark:text-slate-400">{scan.start_time}</td>
              <td className="px-4 py-2">
                <StatusBadge status={scan.status} />
              </td>
              <td className="px-4 py-2">
                {scan.vulnerability_count > 0 ? (
                  <span className="font-semibold text-red-600 dark:text-red-400">{scan.vulnerability_count}</span>
                ) : (
                  <span className="text-slate-500">0</span>
                )}
              </td>
              <td className="px-4 py-2 text-right">
                <button
                  type="button"
                  onClick={() => onDelete(scan.id)}
                  className="text-xs text-slate-500 hover:text-red-600 dark:hover:text-red-400"
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
