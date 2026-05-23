/**
 * skills.sh adapter — Vercel Labs, decentralized GitHub-hosted
 * No public REST API; skills are installed via GitHub URLs
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import { MarketplaceSource, FetchedSkill, FetchOptions } from './types';

const execAsync = promisify(exec);

export class SkillsShAdapter implements MarketplaceSource {
  name = 'skills.sh';

  canHandle(url: string): boolean {
    // skills.sh skills are GitHub repos referenced by skills.sh URLs
    // or direct GitHub URLs that match known skills.sh patterns
    return (
      url.startsWith('https://skills.sh/') ||
      url.startsWith('https://github.com/vercel-labs/skills') ||
      url.startsWith('https://github.com/') // Fallback: any GitHub repo could be a skill
    );
  }

  async fetch(url: string, opts?: FetchOptions): Promise<FetchedSkill> {
    const cacheDir = opts?.cacheDir || path.join(os.homedir(), '.cache', 'skill-scanner', 'skills-sh');
    const ttlMs = (opts?.cacheTtlHours || 24) * 60 * 60 * 1000;

    // Normalize GitHub URL
    const githubUrl = this.normalizeToGitHubUrl(url);
    const repoName = this.extractRepoName(githubUrl);
    const destDir = path.join(cacheDir, repoName);
    const metaPath = path.join(destDir, '.skill-scanner-meta.json');

    // Check cache
    if (!opts?.force && fs.existsSync(metaPath)) {
      try {
        const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
        const age = Date.now() - new Date(meta.fetchedAt).getTime();
        if (age < ttlMs) {
          return this.buildFetchedSkill(destDir, url, repoName, true);
        }
      } catch {
        // Cache invalid, refetch
      }
    }

    // Fetch via git clone
    fs.mkdirSync(destDir, { recursive: true });
    await execAsync(`git clone --depth 1 "${githubUrl}" "${destDir}"`, {
      timeout: 30000,
    });

    // Write metadata
    fs.writeFileSync(
      metaPath,
      JSON.stringify({ fetchedAt: new Date().toISOString(), url: githubUrl }, null, 2)
    );

    return this.buildFetchedSkill(destDir, url, repoName, false);
  }

  private normalizeToGitHubUrl(url: string): string {
    if (url.startsWith('https://skills.sh/')) {
      // skills.sh URLs redirect to GitHub; for v0.1 we require direct GitHub URL
      // In v0.2 we could resolve the redirect
      throw new Error(
        'skills.sh short URLs not yet supported. Please provide the full GitHub URL.'
      );
    }
    return url;
  }

  private extractRepoName(githubUrl: string): string {
    const match = githubUrl.match(/github\.com\/([^/]+\/[^/]+)/);
    return match ? match[1].replace(/\//g, '--') : 'unknown';
  }

  private buildFetchedSkill(
    destDir: string,
    url: string,
    repoName: string,
    fromCache: boolean
  ): FetchedSkill {
    let skillName = repoName;
    const skillMdPath = path.join(destDir, 'SKILL.md');
    if (fs.existsSync(skillMdPath)) {
      try {
        const content = fs.readFileSync(skillMdPath, 'utf-8');
        const nameMatch = content.match(/^name:\s*(.+)$/m);
        if (nameMatch) skillName = nameMatch[1].trim();
      } catch {
        // ignore
      }
    }

    return {
      path: destDir,
      source: this.name,
      url,
      skillName,
      fetchedAt: new Date().toISOString(),
      fromCache,
      cleanup: async () => {
        // Keep cached copies; explicit rm only if --no-cache
      },
    };
  }
}
