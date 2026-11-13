import type { AgentContext, BaseRecord, Query, SimpleQuery } from '@credo-ts/core'
import { AnonCredsModuleConfig } from '../AnonCredsModuleConfig'
import type { AnonCredsProofRequest, AnonCredsProofRequestRestriction } from '../models'

const restrictionIdentifierKeys = ['schema_id', 'cred_def_id', 'rev_reg_id'] as const

/**
 * Returns all known forms of an identifier, with its canonical form first.
 */
export function getIdentifierVariants(agentContext: AgentContext, identifier: string): string[] {
  if (!agentContext.dependencyManager.isRegistered(AnonCredsModuleConfig, true)) return [identifier]

  const registry = agentContext.dependencyManager
    .resolve(AnonCredsModuleConfig)
    .registries.find((registry) => registry.supportedIdentifier.test(identifier))
  const registryVariants = registry?.getIdentifierVariants?.(identifier) ?? [identifier]
  const variants = [...new Set(registryVariants)]

  return variants.includes(identifier) ? variants : [...variants, identifier]
}

export function areIdentifiersEqual(
  agentContext: AgentContext,
  identifierA: string | undefined,
  identifierB: string | undefined
): boolean {
  if (identifierA === identifierB) return true
  if (identifierA === undefined || identifierB === undefined) return false

  return getIdentifierVariants(agentContext, identifierA)[0] === getIdentifierVariants(agentContext, identifierB)[0]
}

// biome-ignore lint/suspicious/noExplicitAny: matches the Query type of core
function variantsQuery<T extends BaseRecord<any, any, any>>(tagName: string, variants: string[]): Query<T> {
  if (variants.length === 1) return { [tagName]: variants[0] } as Query<T>

  return { $or: variants.map((variant) => ({ [tagName]: variant }) as Query<T>) }
}

/**
 * Creates a query matching a tag against every known form of an identifier.
 */
// biome-ignore lint/suspicious/noExplicitAny: matches the Query type of core
export function identifierQuery<T extends BaseRecord<any, any, any>>(
  agentContext: AgentContext,
  tagName: string,
  identifier: string
): Query<T> {
  return variantsQuery<T>(tagName, getIdentifierVariants(agentContext, identifier))
}

/**
 * Adds variant matching for selected identifier tags while preserving the other query filters.
 */
// biome-ignore lint/suspicious/noExplicitAny: matches the Query type of core
export function withIdentifierQueryVariants<T extends BaseRecord<any, any, any>>(
  agentContext: AgentContext,
  query: SimpleQuery<T>,
  tagNames: string[]
): Query<T> {
  const simpleQuery: Record<string, unknown> = { ...query }
  const identifierQueries: Query<T>[] = []

  for (const tagName of tagNames) {
    const identifier = simpleQuery[tagName]
    if (typeof identifier !== 'string') continue

    const variants = getIdentifierVariants(agentContext, identifier)
    if (variants.length === 1) continue

    delete simpleQuery[tagName]
    identifierQueries.push(variantsQuery<T>(tagName, variants))
  }

  if (identifierQueries.length === 0) return query
  return { $and: [simpleQuery as SimpleQuery<T>, ...identifierQueries] }
}

/**
 * Adds aliases for native proof lookups without replacing explicitly supplied keys.
 */
export function withIdentifierVariantKeys<T>(
  agentContext: AgentContext,
  objects: Record<string, T>
): Record<string, T> {
  const withVariants: Record<string, T> = {}
  for (const [identifier, object] of Object.entries(objects)) {
    for (const variant of getIdentifierVariants(agentContext, identifier)) {
      withVariants[variant] ??= object
    }
  }

  return { ...withVariants, ...objects }
}

export function withRestrictionVariants(
  agentContext: AgentContext,
  restrictions: AnonCredsProofRequestRestriction[]
): AnonCredsProofRequestRestriction[] {
  return restrictions.flatMap((restriction) => {
    const identifierVariants = restrictionIdentifierKeys.flatMap((key) => {
      const identifier = restriction[key]
      if (!identifier) return []

      const variants = getIdentifierVariants(agentContext, identifier)
      return variants.length > 1 ? [{ key, variants }] : []
    })

    return identifierVariants.reduce(
      (expanded, { key, variants }) =>
        expanded.flatMap((item) => variants.map((variant) => ({ ...item, [key]: variant }))),
      [restriction]
    )
  })
}

function mapProofRequestRestrictions(
  proofRequest: AnonCredsProofRequest,
  map: (restrictions: AnonCredsProofRequestRestriction[]) => AnonCredsProofRequestRestriction[]
): AnonCredsProofRequest {
  const mapItems = <T extends { restrictions?: AnonCredsProofRequestRestriction[] }>(items: Record<string, T>) =>
    Object.fromEntries(
      Object.entries(items).map(([referent, item]) => [
        referent,
        item.restrictions ? { ...item, restrictions: map(item.restrictions) } : item,
      ])
    )

  return {
    ...proofRequest,
    requested_attributes: mapItems(proofRequest.requested_attributes),
    requested_predicates: mapItems(proofRequest.requested_predicates),
  }
}

export function withProofRequestRestrictionVariants(
  agentContext: AgentContext,
  proofRequest: AnonCredsProofRequest
): AnonCredsProofRequest {
  return mapProofRequestRestrictions(proofRequest, (restrictions) =>
    withRestrictionVariants(agentContext, restrictions)
  )
}

/**
 * Canonicalizes restriction identifiers before semantic proof-request comparisons.
 */
export function withCanonicalRestrictionIdentifiers(
  agentContext: AgentContext,
  proofRequest: AnonCredsProofRequest
): AnonCredsProofRequest {
  return mapProofRequestRestrictions(proofRequest, (restrictions) =>
    restrictions.map((restriction) => {
      const canonical = { ...restriction }
      for (const key of restrictionIdentifierKeys) {
        const identifier = canonical[key]
        if (identifier) canonical[key] = getIdentifierVariants(agentContext, identifier)[0]
      }
      return canonical
    })
  )
}
