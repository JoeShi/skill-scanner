export * from './types';
export { JsonReporter } from './json';
export { MarkdownReporter } from './markdown';
export { TerminalReporter } from './terminal';
export { SarifReporter } from './sarif';

import { Reporter, ReporterFormat } from './types';
import { JsonReporter } from './json';
import { MarkdownReporter } from './markdown';
import { TerminalReporter } from './terminal';
import { SarifReporter } from './sarif';

export function createReporter(format: ReporterFormat): Reporter {
  switch (format) {
    case 'json':
      return new JsonReporter();
    case 'markdown':
      return new MarkdownReporter();
    case 'sarif':
      return new SarifReporter();
    case 'terminal':
    default:
      return new TerminalReporter();
  }
}
