export const PHASE_LABELS: Record<string, string> = {
  crawling: 'Crawling site',
  header_analysis: 'Analyzing security headers',
  cookie_scan: 'Checking cookie security',
  xss_scan: 'Testing for XSS',
  sqli_scan: 'Testing for SQL injection',
  directory_fuzzing: 'Fuzzing directories',
  csrf_scan: 'Checking CSRF protection',
  ssl_scan: 'Checking SSL/TLS config',
  command_injection_scan: 'Testing for command injection',
  idor_scan: 'Testing for IDOR',
  lfi_scan: 'Testing for LFI / path traversal',
  ssrf_scan: 'Testing for SSRF',
  cors_scan: 'Checking CORS config',
  xxe_scan: 'Testing for XXE',
  open_redirect_scan: 'Testing for open redirects',
  generating_report: 'Generating report',
};

export function phaseLabel(phase: string | null | undefined): string {
  if (!phase) return 'Starting…';
  return PHASE_LABELS[phase] ?? phase;
}
