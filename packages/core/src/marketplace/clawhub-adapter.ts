/**
 * ClawHub adapter — OpenClaw community marketplace
 * REST API driven, read operations need no auth
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import https from 'https';
import { MarketplaceSource, FetchedSkill, FetchOptions } from './types';

// v0.1: API base may redirect between .com and .ai — adapter follows redirects
// with a safety limit. Update this constant once the canonical endpoint stabilizes.
const CLAWHUB_API_BASE = 'https://clawdhub.com/api/v1';
const MAX_REDIRECTS = 5;

export class ClawHubAdapter implements MarketplaceSource {
  name = 'clawhub';

  canHandle(url: string): boolean {
    return (
      url.startsWith('https://clawdhub.com/') ||
      url.startsWith('https://clawdhub.ai/') ||
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
    if (url.startsWith('https://clawdhub.com/skills/') || url.startsWith('https://clawdhub.ai/skills/')) {
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
    const url = `${CLAWHUB_API_BASE}${endpoint}`;
    const data = await this.httpGet(url);
    try {
      return JSON.parse(data);
    } catch {
      throw new Error(`Invalid JSON from ${url}`);
    }
  }

  /**
   * HTTP GET with redirect following (up to MAX_REDIRECTS).
   * Handles 301/302/308 redirects across host changes (.com ↔ .ai).
   */
  private httpGet(url: string, redirectCount = 0): Promise<string> {
    return new Promise((resolve, reject) => {
      if (redirectCount > MAX_REDIRECTS) {
        reject(new Error(`Too many redirects (> ${MAX_REDIRECTS}) for ${url}`));
        return;
      }

      const parsedUrl = new URL(url);
      const requestOptions = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: { 'User-Agent': 'skill-scanner/0.1.0' },
        timeout: 15000,
      };

      https
        .request(requestOptions, (res) => {
          if (res.statusCode && [301, 302, 308].includes(res.statusCode)) {
            const loc = res.headers.location;
            if (loc) {
              const nextUrl = loc.startsWith('http') ? loc : new URL(loc, url).href;
              this.httpGet(nextUrl, redirectCount + 1).then(resolve).catch(reject);
              return;
            }
          }

          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            if (res.statusCode && res.statusCode >= 400) {
              reject(new Error(`HTTP ${res.statusCode} from ${url}: ${data.slice(0, 200)}`));
            } else {
              resolve(data);
            }
          });
        })
        .on('error', reject)
        .on('timeout', () => reject(new Error(`Timeout: ${url}`)))
        .end();
    });
  }

  private async downloadFile(url: string, destDir: string): Promise<void> {
    const data = await this.httpGet(url);
    try {
      const files = JSON.parse(data);
      // Write files to destDir
      for (const [filePath, content] of Object.entries(files)) {
        const fullPath = path.join(destDir, filePath);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, content as string);
      }
    } catch {
      // If not JSON, write as single file
      fs.writeFileSync(path.join(destDir, 'SKILL.md'), data);
    }
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
