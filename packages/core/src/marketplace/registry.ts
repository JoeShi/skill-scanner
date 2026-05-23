import { MarketplaceSource, MarketplaceRegistry } from './types';

export class DefaultMarketplaceRegistry implements MarketplaceRegistry {
  private sources: MarketplaceSource[] = [];

  register(source: MarketplaceSource): void {
    this.sources.push(source);
  }

  findSource(url: string): MarketplaceSource | undefined {
    return this.sources.find((s) => s.canHandle(url));
  }

  listSources(): string[] {
    return this.sources.map((s) => s.name);
  }
}

export function createDefaultRegistry(): MarketplaceRegistry {
  const registry = new DefaultMarketplaceRegistry();
  // Adapters registered by CLI main entry
  return registry;
}
