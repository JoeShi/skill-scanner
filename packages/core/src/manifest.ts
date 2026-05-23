import * as fs from 'fs';
import * as path from 'path';
import YAML from 'yaml';
import { SkillManifest, CapabilityDeclaration } from './types';

export const REQUIRED_MANIFEST_FIELDS = [
  'name',
  'version',
  'description',
  'main',
  'author',
  'license',
];

/**
 * Parse skill manifest from JSON file.
 * Falls back to SKILL.md YAML frontmatter if manifest.json is absent.
 */
export function parseManifest(skillPath: string): SkillManifest {
  const manifestPath = path.join(skillPath, 'manifest.json');
  if (fs.existsSync(manifestPath)) {
    const raw = fs.readFileSync(manifestPath, 'utf-8');
    const manifest = JSON.parse(raw) as SkillManifest;
    return normalizeManifest(manifest);
  }

  // Fallback: parse SKILL.md frontmatter
  const skillMdPath = path.join(skillPath, 'SKILL.md');
  if (fs.existsSync(skillMdPath)) {
    const raw = fs.readFileSync(skillMdPath, 'utf-8');
    const manifest = parseSkillMdFrontmatter(raw, skillPath);
    return normalizeManifest(manifest);
  }

  throw new Error(
    `manifest.json not found at ${manifestPath} and no SKILL.md frontmatter available`
  );
}

/**
 * Parse manifest with raw text preserved
 */
export function parseManifestWithRaw(skillPath: string): {
  manifest: SkillManifest;
  raw: string;
} {
  const manifestPath = path.join(skillPath, 'manifest.json');
  if (fs.existsSync(manifestPath)) {
    const raw = fs.readFileSync(manifestPath, 'utf-8');
    const manifest = JSON.parse(raw) as SkillManifest;
    return { manifest: normalizeManifest(manifest), raw };
  }

  const skillMdPath = path.join(skillPath, 'SKILL.md');
  if (fs.existsSync(skillMdPath)) {
    const raw = fs.readFileSync(skillMdPath, 'utf-8');
    const manifest = parseSkillMdFrontmatter(raw, skillPath);
    return { manifest: normalizeManifest(manifest), raw };
  }

  throw new Error(
    `manifest.json not found at ${manifestPath} and no SKILL.md frontmatter available`
  );
}

/**
 * Normalize manifest fields across marketplace sources:
 * - skills.sh: YAML frontmatter in SKILL.md (name, version, capabilities, domains, etc.)
 * - ClawHub: JSON manifest with installer + env fields
 * - Legacy: plain manifest.json
 *
 * Normalizations applied:
 * 1. `version` — ensure present (default '0.0.0' if missing)
 * 2. `publisher` — copy from `author` or `publisher` if either present
 * 3. `installer` — normalize `installer.type` to lowercase, validate shape
 * 4. `env` — ensure it's a Record<string, string>
 */
export function normalizeManifest(manifest: SkillManifest): SkillManifest {
  const normalized: SkillManifest = {
    ...manifest,
    name: manifest.name || 'unknown',
    version: manifest.version || '0.0.0',
  };

  // Normalize publisher / vendor field
  if (!normalized.publisher && normalized.author) {
    normalized.publisher = normalized.author;
  }

  // Normalize installer shape
  if (normalized.installer) {
    if (typeof normalized.installer !== 'object') {
      delete normalized.installer;
    } else {
      normalized.installer = {
        type: normalized.installer.type,
        command: normalized.installer.command,
        script: normalized.installer.script,
      };
      if (normalized.installer.type) {
        normalized.installer.type = normalized.installer.type.toLowerCase();
      }
    }
  }

  // Normalize env shape
  if (normalized.env) {
    if (typeof normalized.env !== 'object' || Array.isArray(normalized.env)) {
      delete normalized.env;
    } else {
      const cleanEnv: Record<string, string> = {};
      for (const [k, v] of Object.entries(normalized.env)) {
        cleanEnv[k] = String(v);
      }
      normalized.env = cleanEnv;
    }
  }

  return normalized;
}

/**
 * Parse SKILL.md YAML frontmatter into a SkillManifest.
 *
 * skills.sh / ClawHub frontmatter format:
 * ```yaml
 * ---
 * name: my-skill
 * version: 1.0.0
 * description: Does something
 * capabilities:
 *   - resource: fs.read
 *     scope: /tmp
 * domains:
 *   - api.example.com
 * installer:
 *   type: orchestrator-managed
 * env:
 *   FOO: bar
 * ---
 * ```
 */
export function parseSkillMdFrontmatter(
  content: string,
  skillPath: string
): SkillManifest {
  const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n/);
  if (!frontmatterMatch) {
    // No frontmatter — create a minimal manifest from directory name
    return {
      name: path.basename(skillPath),
      version: '0.0.0',
    } as SkillManifest;
  }

  const yamlText = frontmatterMatch[1];
  const parsed = YAML.parse(yamlText) || {};

  const manifest: SkillManifest = {
    name: parsed.name || path.basename(skillPath),
    version: parsed.version || '0.0.0',
    description: parsed.description,
    capabilities: parsed.capabilities,
    domains: parsed.domains,
    fsPaths: parsed.fsPaths,
    main: parsed.main,
    dependencies: parsed.dependencies,
    devDependencies: parsed.devDependencies,
    author: parsed.author,
    publisher: parsed.publisher || parsed.author,
    license: parsed.license,
    installer: parsed.installer,
    env: parsed.env,
  };

  return manifest;
}

/**
 * Validate manifest structure (required fields, semver, etc.)
 * Returns array of validation error messages
 */
export function validateManifestStructure(
  manifest: SkillManifest
): string[] {
  const errors: string[] = [];

  for (const field of REQUIRED_MANIFEST_FIELDS) {
    if (!(field in manifest) || manifest[field] == null) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // semver check
  if (manifest.version) {
    const semverRegex =
      /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([\da-z-]+(?:\.[\da-z-]+)*))?(?:\+([\da-z-]+(?:\.[\da-z-]+)*))?$/i;
    if (!semverRegex.test(manifest.version)) {
      errors.push(`Invalid semver: ${manifest.version}`);
    }
  }

  // capability declarations validation
  if (manifest.capabilities) {
    if (typeof manifest.capabilities !== 'object') {
      errors.push('capabilities must be an object');
    }
  }

  // domains validation
  if (manifest.domains) {
    if (!Array.isArray(manifest.domains)) {
      errors.push('domains must be an array');
    }
  }

  // installer validation
  if (manifest.installer) {
    if (typeof manifest.installer !== 'object') {
      errors.push('installer must be an object');
    } else if (
      manifest.installer.type &&
      typeof manifest.installer.type !== 'string'
    ) {
      errors.push('installer.type must be a string');
    }
  }

  // env validation
  if (manifest.env) {
    if (typeof manifest.env !== 'object' || Array.isArray(manifest.env)) {
      errors.push('env must be an object');
    }
  }

  return errors;
}

/**
 * Extract declared capabilities as a map for diff scanning
 */
export function extractDeclaredCapabilities(
  manifest: SkillManifest
): Map<string, string> {
  const map = new Map<string, string>();
  if (!manifest.capabilities) return map;
  for (const cap of manifest.capabilities) {
    const key = cap.scope ? `${cap.resource}:${cap.scope}` : cap.resource;
    map.set(key, cap.name);
  }
  return map;
}

/**
 * Extract declared domains as a Set
 */
export function extractDeclaredDomains(manifest: SkillManifest): Set<string> {
  return new Set(manifest.domains || []);
}
