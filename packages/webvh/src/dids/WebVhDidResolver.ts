import type { AgentContext, DidResolutionResult, DidResolver, ParsedDid } from '@credo-ts/core'

import { DidDocument } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import { didWebvhToHttps, getResolver, parseDidWebvhUrl } from 'didwebvh-ts'

export class WebVhDidResolver implements DidResolver {
  public readonly supportedMethods = ['webvh']
  public readonly allowsCaching = true
  public readonly allowsLocalDidRecord = true

  /**
   * Resolves published logs through upstream's dispatcher, parser hook, and version-selector handling.
   *
   * @param agentContext Agent context providing storage, KMS, and configured fetch.
   * @param did Bare WebVH DID supplied by Credo.
   * @param parsed Credo-parsed original DID URL, including any version query.
   * @returns DID document and upstream metadata, or resolution error metadata.
   */
  public async resolve(agentContext: AgentContext, did: string, parsed: ParsedDid): Promise<DidResolutionResult> {
    try {
      const resolver = new Resolver(getResolver({ fetch: agentContext.config.fetch.bind(agentContext.config) }), {
        cache: false,
      })
      const result = await resolver.resolve(parsed.didUrl)
      return {
        didDocument: result.didDocument ? DidDocument.fromJSON(result.didDocument) : null,
        didDocumentMetadata: result.didDocumentMetadata,
        didResolutionMetadata: result.didResolutionMetadata,
      }
    } catch (error) {
      agentContext.config.logger.error(`Error resolving DID ${did}`, error)
      return {
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: 'internalError',
          message: `Unable to resolve DID '${did}': ${error instanceof Error ? error.message : String(error)}`,
        },
      }
    }
  }

  /**
   * Fetches a WebVH resource with the agent's fetch limits, returning dereferencing metadata or an explicit error.
   *
   * @param agentContext Agent context providing configured fetch and logging.
   * @param resourceUrl WebVH DID URL identifying the resource.
   * @returns Resource content and retrieval metadata, or a resolution error and message.
   */
  public async resolveResource(agentContext: AgentContext, resourceUrl: string) {
    try {
      agentContext.config.logger.debug(`Attempting to resolve resource: ${resourceUrl}`)

      const parsed = parseDidWebvhUrl(resourceUrl)
      const httpsUrl = `${didWebvhToHttps(parsed.did)}${parsed.path ?? ''}${parsed.query ? `?${parsed.query}` : ''}`

      agentContext.config.logger.debug(`Fetching resource from: ${httpsUrl}`)

      const response = await agentContext.config.fetch(httpsUrl)

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const contentType = response.headers.get('content-type') || 'application/json'
      const mediaType = contentType.split(';')[0].trim().toLowerCase()
      let content: Record<string, unknown> | unknown[] | string

      // Structured JSON types such as application/ld+json use the +json suffix (RFC 6839).
      if (mediaType === 'application/json' || mediaType.endsWith('+json')) {
        content = (await response.json()) as Record<string, unknown>
      } else {
        content = await response.text()
      }

      agentContext.config.logger.debug(`Successfully fetched resource, content type: ${contentType}`)

      return {
        content,
        contentMetadata: {
          contentType,
          retrieved: new Date().toISOString(),
        },
        dereferencingMetadata: {
          contentType,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error resolving resource ${resourceUrl}:`, error)
      return {
        error: 'notFound',
        message: `resolver_error: Unable to resolve resource '${resourceUrl}': ${error instanceof Error ? error.message : String(error)}`,
      }
    }
  }
}
