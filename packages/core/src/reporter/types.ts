import { ScanResult } from '../types';

export interface Reporter {
  name: string;
  render(result: ScanResult): string;
}

export type ReporterFormat = 'terminal' | 'json' | 'markdown' | 'sarif';
