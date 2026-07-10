import { Link, Outlet } from 'react-router-dom';

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-slate-200 dark:border-slate-800">
        <div className="mx-auto max-w-5xl px-4 py-4 flex items-center gap-2">
          <Link to="/" className="flex items-center gap-2 font-semibold text-lg">
            <span aria-hidden="true">🛡️</span>
            SecuritScanner
          </Link>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-8">
        <Outlet />
      </main>
    </div>
  );
}
