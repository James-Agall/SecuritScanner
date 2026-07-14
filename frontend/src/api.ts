import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
});

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Scan {
  id: number;
  target_url: string;
  start_time: string;
  status: ScanStatus;
  current_phase: string | null;
  vulnerability_count: number;
}

export interface Vulnerability {
  id: number;
  scan_id: number;
  type: string;
  severity: Severity;
  url: string;
  vulnerable_param: string;
  payload_used: string;
  description: string;
  remediation: string;
}

export interface ScanCreateRequest {
  target_url: string;
  max_pages?: number;
  allowed_domains?: string[];
  allowed_ports?: number[];
  allow_local_testing?: boolean;
  stealth_mode?: boolean;
  test_username?: string;
  test_password?: string;
}

export async function listScans(): Promise<Scan[]> {
  const { data } = await api.get<Scan[]>('/scans');
  return data;
}

export async function getScan(id: number): Promise<Scan> {
  const { data } = await api.get<Scan>(`/scans/${id}`);
  return data;
}

export async function createScan(request: ScanCreateRequest): Promise<Scan> {
  const { data } = await api.post<Scan>('/scans', request);
  return data;
}

export async function deleteScan(id: number): Promise<void> {
  await api.delete(`/scans/${id}`);
}

export async function getVulnerabilities(scanId: number): Promise<Vulnerability[]> {
  const { data } = await api.get<Vulnerability[]>(`/scans/${scanId}/vulnerabilities`);
  return data;
}

export function reportUrl(scanId: number, format: 'html' | 'pdf'): string {
  return `${API_BASE_URL}/scans/${scanId}/report?format=${format}`;
}
