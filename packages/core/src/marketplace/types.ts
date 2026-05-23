/**
 * Marketplace adapter types
 * Abstracts fetching skills from different marketplaces
 */

export interface MarketplaceSource {
  name: string;
  /** Recognizes if a URL or identifier belongs to this marketplace */
  canHandle(url: string): boolean;
  /** Fetch skill package to a temp directory */
  fetch(url: string, opts?: FetchOptions): Promise<FetchedSkill>;
}

export interface FetchOptions {
  /** Cache directory (default: ~/.cache/skill-scanner/) */
  cacheDir?: string;
  /** TTL in hours (default: 24) */
  cacheTtlHours?: number;
  /** Force refetch even if cached */
  force?: boolean;
}

export interface FetchedSkill {
  /** Local directory where skill is unpacked */
  path: string;
  /** Marketplace source name */
  source: string;
  /** Original URL/identifier */
  url: string;
  /** Skill name from manifest or URL */
  skillName: string;
  /** When fetched */
  fetchedAt: string;
  /** Whether this is a cached copy */
  fromCache: boolean;
  /** Cleanup function — must call when done scanning */
  cleanup: () => Promise<void>;
}

export interface MarketplaceRegistry {
  register(source: MarketplaceSource): void;
  findSource(url: string): MarketplaceSource | undefined;
  listSources(): string[];
}
