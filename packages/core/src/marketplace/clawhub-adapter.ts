/**
 * ClawHub adapter — OpenClaw community marketplace
 * REST API driven, read operations need no auth
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import https from 'https';
import { MarketplaceSource, FetchedSkill, FetchOptions } from './types';

const CLAWHUB_API_BASE = 'https://clawdhub.com/api/v1';

export class ClawHubAdapter implements MarketplaceSource {
  name = 'clawhub';

  canHandle(url: string): boolean {
    return (
      url.startsWith('https://clawdhub.com/') ||
      url.startsWith('https://github.com/openclaw/') ||
      /^[a-z0-9-]+$/i.test(url) // Simple slug like "my-skill"
    );
  }

  async fetch(url: string, opts?: FetchOptions): Promise<FetchedSkill> {
    const cacheDir = opts?.cacheDir || path.join(os.homedir(), '.cache', 'skill-scanner', 'clawhub');
    const ttlMs = (opts?.cacheTtlHours || 24) * 60 * 60 * 1000;

    const slug = this.extractSlug(url);
    const destDir = path.join(cacheDir, slug);
    const metaPath = path.join(destDir, '.skill-scanner-meta.json');

    // Check cache
    if (!opts?.force && fs.existsSync(metaPath)) {
      try {
        const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
        const age = Date.now() - new Date(meta.fetchedAt).getTime();
        if (age < ttlMs) {
          return this.buildFetchedSkill(destDir, url, slug, true);
        }
      } catch {
        // Cache invalid
      }
    }

    // Fetch from ClawHub API
    fs.mkdirSync(destDir, { recursive: true });

    // 1. Get skill metadata
    const skillMeta = await this.apiGet(`/skills/${slug}`);
    const skillName = skillMeta.name || slug;
    const version = skillMeta.version || 'latest';

    // 2. Download skill files
    const fileUrl = `${CLAWHUB_API_BASE}/skills/${slug}/file`;
    await this.downloadFile(fileUrl, destDir);

    // 3. Optionally fetch ClawHub's own scan results for cross-reference
    try {
      const clawhubScan = await this.apiGet(`/skills/${slug}/scan`);
      fs.writeFileSync(
        path.join(destDir, '.clawhub-scan.json'),
        JSON.stringify(clawhubScan, null, 2)
      );
    } catch {
      // ClawHub scan endpoint may not exist for all skills
    }

    // Write metadata
    fs.writeFileSync(
      metaPath,
      JSON.stringify(
        { fetchedAt: new Date().toISOString(), url, slug, version, skillName },
        null,
        2
      )
    );

    return this.buildFetchedSkill(destDir, url, skillName, false);
  }

  private extractSlug(url: string): string {
    if (url.startsWith('https://clawdhub.com/skills/')) {
      const match = url.match(/\/skills\/([^/?]+)/);
      return match ? match[1] : url;
    }
    if (url.startsWith('https://github.com/openclaw/')) {
      return url.split('/').pop() || url;
    }
    // Assume it's already a slug
    return url;
  }

  private async apiGet(endpoint: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const url = `${CLAWHUB_API_BASE}${endpoint}`;
      https
        .get(url, { headers: { 'User-Agent': 'skill-scanner/0.1.0' } }, (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch {
              reject(new Error(`Invalid JSON from ${url}`));
            }
          });
        })
        .on('error', reject)
        .setTimeout(15000, () => reject(new Error(`Timeout: ${url}`)));
    });
  }

  private async downloadFile(url: string, destDir: string): Promise<void> {
    return new Promise((resolve, reject) => {
      https
        .get(url, { headers: { 'User-Agent': 'skill-scanner/0.1.0' } }, (res) => {
          if (res.statusCode === 302 || res.statusCode === 301) {
            // Follow redirect
            const redirectUrl = res.headers.location;
            if (redirectUrl) {
              this.downloadFile(redirectUrl, destDir).then(resolve).catch(reject);
              return;
            }
          }

          // For v0.1, assume the file is a tarball or zip
          // In production, we'd stream to a temp file and extract
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              const files = JSON.parse(data);
              // Write files to destDir
              for (const [filePath, content] of Object.entries(files)) {
                const fullPath = path.join(destDir, filePath);
                fs.mkdirSync(path.dirname(fullPath), { recursive: true });
                fs.writeFileSync(fullPath, content as string);
              }
              resolve();
            } catch {
              // If not JSON, write as single file
              fs.writeFileSync(path.join(destDir, 'SKILL.md'), data);
              resolve();
            }
          });
        })
        .on('error', reject)
        .setTimeout(30000, () => reject(new Error(`Timeout: ${url}`)));
    });
  }

  private buildFetchedSkill(
    destDir: string,
    url: string,
    skillName: string,
    fromCache: boolean
  ): FetchedSkill {
    return {
      path: destDir,
      source: this.name,
      url,
      skillName,
      fetchedAt: new Date().toISOString(),
      fromCache,
      cleanup: async () => {
        // Keep cache by default
      },
    };
  }
}
