/**
 * Marketplace adapters — unified skill fetching from multiple sources
 */

export * from './types';
export * from './registry';
export * from './local-adapter';
export * from './skills-sh-adapter';
export * from './clawhub-adapter';

import { createDefaultRegistry } from './registry';
import { LocalDirectoryAdapter } from './local-adapter';
import { SkillsShAdapter } from './skills-sh-adapter';
import { ClawHubAdapter } from './clawhub-adapter';

export function createMarketplaceRegistryWithDefaults() {
  const registry = createDefaultRegistry();
  registry.register(new LocalDirectoryAdapter());
  registry.register(new SkillsShAdapter());
  registry.register(new ClawHubAdapter());
  return registry;
}
