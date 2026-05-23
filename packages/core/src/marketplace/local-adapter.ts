/**
 * Local directory adapter — scan an already-downloaded skill package
 */

import * as fs from 'fs';
import * as path from 'path';
import { MarketplaceSource, FetchedSkill } from './types';

export class LocalDirectoryAdapter implements MarketplaceSource {
  name = 'local';

  canHandle(url: string): boolean {
    // Absolute or relative path that exists as directory
    try {
      const resolved = path.resolve(url);
      return fs.existsSync(resolved) && fs.statSync(resolved).isDirectory();
    } catch {
      return false;
    }
  }

  async fetch(url: string): Promise<FetchedSkill> {
    const resolved = path.resolve(url);
    const manifestPath = path.join(resolved, 'manifest.json');
    let skillName = path.basename(resolved);

    if (fs.existsSync(manifestPath)) {
      try {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
        skillName = manifest.name || skillName;
      } catch {
        // ignore parse error, use directory name
      }
    }

    return {
      path: resolved,
      source: this.name,
      url: resolved,
      skillName,
      fetchedAt: new Date().toISOString(),
      fromCache: true,
      cleanup: async () => {
        // No cleanup needed for local paths
      },
    };
  }
}
