// Apply the allowlist to an analysis and decide the result.
import { lookupAllowed, connectionAllowed } from './allow.js';

export function verdict(analysis, rules = []) {
  const lookups = analysis.lookups.map((l) => ({ ...l, allowed: lookupAllowed(rules, l.name) }));
  const connections = analysis.connections.map((c) => ({ ...c, allowed: connectionAllowed(rules, c) }));
  const unexpected = lookups.filter((l) => !l.allowed).length + connections.filter((c) => !c.allowed).length;
  const allowed = lookups.filter((l) => l.allowed).length + connections.filter((c) => c.allowed).length;
  return {
    ...analysis,
    lookups,
    connections,
    summary: {
      egress: lookups.length + connections.length,
      unexpected,
      unexpectedLookups: lookups.filter((l) => !l.allowed).length,
      unexpectedDestinations: connections.filter((c) => !c.allowed).length,
      allowed,
      lookups: lookups.length,
      destinations: connections.length,
      zeroEgress: lookups.length + connections.length === 0,
    },
  };
}
