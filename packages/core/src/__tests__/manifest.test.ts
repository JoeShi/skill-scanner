import { describe, test, expect } from 'vitest';
import {
  normalizeManifest,
  parseSkillMdFrontmatter,
  validateManifestStructure,
} from '../manifest';
import { SkillManifest } from '../types';

describe('normalizeManifest', () => {
  test('fills missing version with 0.0.0', () => {
    const m = normalizeManifest({ name: 'foo' } as SkillManifest);
    expect(m.version).toBe('0.0.0');
    expect(m.name).toBe('foo');
  });

  test('copies author to publisher when publisher absent', () => {
    const m = normalizeManifest({
      name: 'foo',
      version: '1.0.0',
      author: 'Acme Corp',
    } as SkillManifest);
    expect(m.publisher).toBe('Acme Corp');
    expect(m.author).toBe('Acme Corp');
  });

  test('keeps explicit publisher over author', () => {
    const m = normalizeManifest({
      name: 'foo',
      version: '1.0.0',
      author: 'Alice',
      publisher: 'Acme Corp',
    } as SkillManifest);
    expect(m.publisher).toBe('Acme Corp');
  });

  test('normalizes installer.type to lowercase', () => {
    const m = normalizeManifest({
      name: 'foo',
      version: '1.0.0',
      installer: { type: 'DIRECT-EXEC', command: './run.sh' },
    } as SkillManifest);
    expect(m.installer?.type).toBe('direct-exec');
  });

  test('drops malformed installer', () => {
    const m = normalizeManifest({
      name: 'foo',
      version: '1.0.0',
      installer: 'bad' as any,
    } as SkillManifest);
    expect(m.installer).toBeUndefined();
  });

  test('normalizes env values to strings', () => {
    const m = normalizeManifest({
      name: 'foo',
      version: '1.0.0',
      env: { PORT: 3000, DEBUG: true } as any,
    } as SkillManifest);
    expect(m.env).toEqual({ PORT: '3000', DEBUG: 'true' });
  });

  test('drops malformed env', () => {
    const m = normalizeManifest({
      name: 'foo',
      version: '1.0.0',
      env: ['bad'] as any,
    } as SkillManifest);
    expect(m.env).toBeUndefined();
  });
});

describe('parseSkillMdFrontmatter', () => {
  test('parses full frontmatter', () => {
    const md = `---
name: my-skill
version: 1.2.3
description: A test skill
capabilities:
  - resource: fs.read
    scope: /tmp
domains:
  - api.example.com
installer:
  type: orchestrator-managed
env:
  FOO: bar
---

# Skill
`;
    const m = parseSkillMdFrontmatter(md, '/tmp/my-skill');
    expect(m.name).toBe('my-skill');
    expect(m.version).toBe('1.2.3');
    expect(m.description).toBe('A test skill');
    expect(m.capabilities).toEqual([{ resource: 'fs.read', scope: '/tmp' }]);
    expect(m.domains).toEqual(['api.example.com']);
    expect(m.installer).toEqual({ type: 'orchestrator-managed' });
    expect(m.env).toEqual({ FOO: 'bar' });
  });

  test('falls back to directory name when no frontmatter', () => {
    const m = parseSkillMdFrontmatter('# Just markdown', '/tmp/cool-skill');
    expect(m.name).toBe('cool-skill');
    expect(m.version).toBe('0.0.0');
  });

  test('falls back to directory name when frontmatter is empty', () => {
    const m = parseSkillMdFrontmatter('---\n---\n', '/tmp/cool-skill');
    expect(m.name).toBe('cool-skill');
    expect(m.version).toBe('0.0.0');
  });

  test('normalizes publisher from author', () => {
    const md = `---
name: test
author: Alice
---
`;
    const m = parseSkillMdFrontmatter(md, '/tmp/test');
    expect(m.author).toBe('Alice');
    expect(m.publisher).toBe('Alice');
  });
});

describe('validateManifestStructure', () => {
  test('validates installer and env shapes', () => {
    const errors = validateManifestStructure({
      name: 'foo',
      version: '1.0.0',
      description: 'x',
      main: 'index.js',
      author: 'a',
      license: 'MIT',
      installer: { type: 'direct-exec' },
      env: { PATH: '/bad' },
    } as SkillManifest);
    // installer.type as string is valid; env as object is valid
    expect(errors).toHaveLength(0);
  });

  test('catches malformed installer and env', () => {
    const errors = validateManifestStructure({
      name: 'foo',
      version: '1.0.0',
      description: 'x',
      main: 'index.js',
      author: 'a',
      license: 'MIT',
      installer: 'bad' as any,
      env: ['bad'] as any,
    } as SkillManifest);
    expect(errors).toContain('installer must be an object');
    expect(errors).toContain('env must be an object');
  });
});
