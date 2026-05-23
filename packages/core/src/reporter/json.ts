import { Reporter } from './types';
import { ScanResult } from '../types';

export class JsonReporter implements Reporter {
  name = 'json';

  render(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }
}
