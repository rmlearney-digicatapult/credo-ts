import type {
  AnonCredsCredentialDefinition,
  AnonCredsRegistry,
  AnonCredsRevocationRegistryDefinition,
  AnonCredsRevocationStatusListWithoutTimestamp,
  AnonCredsSchema,
  GetCredentialDefinitionReturn,
  GetRevocationRegistryDefinitionReturn,
  GetRevocationStatusListReturn,
  GetSchemaReturn,
  RegisterCredentialDefinitionOptions,
  RegisterCredentialDefinitionReturn,
  RegisterRevocationRegistryDefinitionOptions,
  RegisterRevocationRegistryDefinitionReturn,
  RegisterRevocationStatusListOptions,
  RegisterRevocationStatusListReturn,
  RegisterSchemaOptions,
  RegisterSchemaReturn,
} from '@credo-ts/anoncreds'

import {
  type AgentContext,
  CredoError,
  DidRepository,
  getPublicJwkFromVerificationMethod,
  Kms,
  keyDidEd25519,
  MultiBaseEncoder,
  MultiHashEncoder,
  type Proof,
  parseDid,
  TypedArrayEncoder,
  type VerificationMethod,
  W3cDataIntegrityApi,
  type W3cDataIntegritySingleProofSecuredDocument,
  type W3cDataIntegrityUnsecuredDocument,
} from '@credo-ts/core'
import { parseDidWebvhUrl } from 'didwebvh-ts'
import { canonicalize } from 'json-canonicalize'
import type { ZodType } from 'zod'
import { getWebVhDidResolver } from '../../dids/getWebVhDidResolver'
import {
  type WebVhAttestedResource,
  type WebVhAttestedResourceInput,
  type WebVhAttestedResourceLink,
  zWebVhAttestedResource,
} from '../../resources/attestedResource'
import {
  zWebVhCredDefContent,
  zWebVhRevRegDefContent,
  zWebVhSchemaContent,
  zWebVhStatusListContent,
} from '../utils/transform'

type DidResourceResolutionResult = {
  error?: string
  message?: string
  content?: Record<string, unknown> | unknown[] | string // More specific than any, but still flexible
  contentMetadata?: Record<string, unknown>
  dereferencingMetadata?: Record<string, unknown>
}

/**
 * Attested resources are always signed with, and verified against, a verification method that is
 * authorized for the `assertionMethod` verification relationship.
 */
const ATTESTED_RESOURCE_PROOF_PURPOSE = 'assertionMethod' as const

/**
 * The only cryptosuite the attested resources specification allows, which signs with Ed25519 keys.
 */
const ATTESTED_RESOURCE_CRYPTOSUITE = 'eddsa-jcs-2022' as const

export class WebVhAnonCredsRegistry implements AnonCredsRegistry {
  public methodName = 'webvh'

  public allowsCaching = true
  public allowsLocalRecord = true

  /**
   * This class supports resolving objects with did:webvh identifiers.
   */
  public readonly supportedIdentifier = /^did:webvh:.*/

  private _digestMultibase(value: string) {
    const valueBytes = TypedArrayEncoder.fromUtf8String(value)
    const digestMultihash = MultiHashEncoder.encode(valueBytes, 'sha-256')
    const digestMultibase = MultiBaseEncoder.encode(digestMultihash, 'base58btc')
    return digestMultibase
  }

  /**
   * Resolves an attested resource and validates its ID, type, content digest, issuer and proof.
   *
   * @param agentContext The agent context.
   * @param resourceId The DID URL of the resource to resolve.
   * @param resourceTypeString A descriptive string for the resource type (e.g., 'schema', 'credential definition') used in logs/errors.
   * @param contentSchema Schema of the content the caller expects.
   * @returns The parsed resource, its parsed content and the original resolution result.
   * @throws {CredoError} If resolution, parsing, or validation fails.
   */
  private async _resolveAndValidateAttestedResource<Content extends { issuerId: string }>(
    agentContext: AgentContext,
    resourceId: string,
    resourceTypeString: string,
    contentSchema: ZodType<Content>
  ): Promise<{
    resourceObject: WebVhAttestedResource
    content: Content
    resolutionResult: DidResourceResolutionResult
  }> {
    let parsedResourceUrl: ReturnType<typeof parseDidWebvhUrl>
    try {
      parsedResourceUrl = parseDidWebvhUrl(resourceId)
    } catch (error) {
      throw new CredoError(`Invalid ${resourceTypeString} ID: ${resourceId}`, {
        cause: error instanceof Error ? error : undefined,
      })
    }

    const resourcePathMatch = parsedResourceUrl.path?.match(/^\/resources\/([^/]+)$/)
    if (parsedResourceUrl.query !== undefined || parsedResourceUrl.fragment !== undefined || !resourcePathMatch) {
      throw new CredoError(`Invalid ${resourceTypeString} ID: ${resourceId}`)
    }
    const expectedMultibaseHash = resourcePathMatch[1]

    agentContext.config.logger.trace(
      `Attempting to resolve ${resourceTypeString} resource '${resourceId}' via did:webvh resolver`
    )

    const resolutionResult = await getWebVhDidResolver(agentContext).resolveResource(agentContext, resourceId)

    if ('error' in resolutionResult || !('content' in resolutionResult)) {
      throw new CredoError(
        `Resource ${resourceId} could not be resolved or is missing data. Error: ${resolutionResult.error || 'unknown'} - ${resolutionResult.message || 'no message'}`
      )
    }

    let resourceObject: WebVhAttestedResource
    let content: Content
    try {
      agentContext.config.logger.trace(
        `Parsing resource data: ${JSON.stringify(resolutionResult.content).substring(0, 200)}...`
      )
      resourceObject = zWebVhAttestedResource.parse(resolutionResult.content)
      content = contentSchema.parse(resourceObject.content)
    } catch (parseError) {
      throw new CredoError(
        `Failed to parse resource data for ${resourceId}: ${
          parseError instanceof Error ? parseError.message : String(parseError)
        }`,
        { cause: parseError instanceof Error ? parseError : undefined }
      )
    }
    // Parsing normalises fields such as `type`, so the proof and digest are checked on the resource as fetched.
    const signedResource = resolutionResult.content as WebVhAttestedResourceInput

    // These checks need no network access, so they run before the proof check resolves the issuer DID.
    const verificationMethodDid = parseDid(resourceObject.proof.verificationMethod).did
    if (verificationMethodDid !== parsedResourceUrl.did) {
      throw new CredoError(
        `Proof verification method DID mismatch for ${resourceId}. Expected: ${parsedResourceUrl.did}, Actual: ${verificationMethodDid}`
      )
    }

    if (content.issuerId !== parsedResourceUrl.did) {
      throw new CredoError(
        `Issuer ID mismatch for ${resourceId}. Expected: ${parsedResourceUrl.did}, Actual: ${content.issuerId}`
      )
    }

    if (resourceObject.id !== resourceId) {
      throw new CredoError(`ID mismatch ${resourceObject.id} != ${resourceId}`)
    }
    const digestMultibase = this._digestMultibase(canonicalize(signedResource.content))
    if (digestMultibase !== expectedMultibaseHash) {
      throw new CredoError(
        `Content hash mismatch for ${resourceId}. Expected: ${expectedMultibaseHash}, Actual: ${digestMultibase}`
      )
    }
    agentContext.config.logger.trace(`Resource ${resourceId} content hash matches filename.`)

    if (!(await this.verifyProof(agentContext, signedResource))) {
      throw new CredoError('Resolved resource proof is invalid.')
    }
    agentContext.config.logger.trace(`Resource ${resourceId} proof validated.`)

    return { resourceObject, content, resolutionResult }
  }

  public async getSchema(agentContext: AgentContext, schemaId: string): Promise<GetSchemaReturn> {
    try {
      const {
        resourceObject,
        content: schemaContent,
        resolutionResult,
      } = await this._resolveAndValidateAttestedResource(agentContext, schemaId, 'schema', zWebVhSchemaContent)

      return {
        schema: {
          attrNames: schemaContent.attrNames,
          name: schemaContent.name,
          version: schemaContent.version,
          issuerId: schemaContent.issuerId,
        },
        schemaId,
        resolutionMetadata: resolutionResult.dereferencingMetadata || {},
        schemaMetadata: resourceObject.metadata || {},
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving schema '${schemaId}' via did:webvh`, {
        error: error instanceof Error ? error.message : String(error),
        schemaId,
      })

      return {
        schemaId,
        resolutionMetadata: {
          error: 'invalid',
          message: `unable to resolve schema: ${error instanceof Error ? error.message : String(error)}`,
        },
        schemaMetadata: {},
      }
    }
  }

  public async getCredentialDefinition(
    agentContext: AgentContext,
    credentialDefinitionId: string
  ): Promise<GetCredentialDefinitionReturn> {
    try {
      const {
        resourceObject,
        content: credDefContent,
        resolutionResult,
      } = await this._resolveAndValidateAttestedResource(
        agentContext,
        credentialDefinitionId,
        'credential definition',
        zWebVhCredDefContent
      )

      // Extract metadata from the resolved resource
      const credDefMetadata = resourceObject.metadata || resolutionResult.contentMetadata || {}

      return {
        credentialDefinition: {
          issuerId: credDefContent.issuerId,
          schemaId: credDefContent.schemaId,
          type: 'CL' as const, // Assuming CL type for now, might need adjustment if other types are supported
          tag: credDefContent.tag,
          value: credDefContent.value as { primary: Record<string, unknown>; revocation?: unknown }, // Assuming structure
        },
        credentialDefinitionId,
        resolutionMetadata: resolutionResult.dereferencingMetadata || {},
        credentialDefinitionMetadata: credDefMetadata,
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error retrieving credential definition '${credentialDefinitionId}' via did:webvh`,
        {
          error: error instanceof Error ? error.message : String(error),
          credentialDefinitionId,
        }
      )

      return {
        credentialDefinitionId,
        resolutionMetadata: {
          error: 'invalid',
          message: `unable to resolve credential definition: ${error instanceof Error ? error.message : String(error)}`,
        },
        credentialDefinitionMetadata: {},
      }
    }
  }

  public async getRevocationRegistryDefinition(
    agentContext: AgentContext,
    revocationRegistryDefinitionId: string
  ): Promise<GetRevocationRegistryDefinitionReturn> {
    try {
      const {
        resourceObject,
        content: revRegDefContent,
        resolutionResult,
      } = await this._resolveAndValidateAttestedResource(
        agentContext,
        revocationRegistryDefinitionId,
        'revocation registry definition',
        zWebVhRevRegDefContent
      )

      // Extract metadata
      const revRegDefMetadata = resourceObject.metadata || resolutionResult.contentMetadata || {}

      return {
        revocationRegistryDefinition: {
          issuerId: revRegDefContent.issuerId,
          revocDefType: revRegDefContent.revocDefType as AnonCredsRevocationRegistryDefinition['revocDefType'], // TODO: Map revocDefType string to AnonCreds type
          credDefId: revRegDefContent.credDefId,
          tag: revRegDefContent.tag,
          value: revRegDefContent.value,
        },
        revocationRegistryDefinitionId,
        resolutionMetadata: resolutionResult.dereferencingMetadata || {},
        revocationRegistryDefinitionMetadata: revRegDefMetadata,
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error retrieving revocation registry definition '${revocationRegistryDefinitionId}' via did:webvh`,
        {
          error: error instanceof Error ? error.message : String(error),
          revocationRegistryDefinitionId,
        }
      )

      return {
        revocationRegistryDefinitionId,
        resolutionMetadata: {
          error: 'invalid',
          message: `unable to resolve revocation registry definition: ${
            error instanceof Error ? error.message : String(error)
          }`,
        },
        revocationRegistryDefinitionMetadata: {},
      }
    }
  }

  public async getRevocationStatusList(
    agentContext: AgentContext,
    revocationRegistryId: string,
    timestamp: number
  ): Promise<GetRevocationStatusListReturn> {
    try {
      agentContext.config.logger.trace(
        `Attempting to resolve revocation status list resource for '${revocationRegistryId}' at timestamp ${timestamp} via did:webvh resolver`
      )
      const { resourceObject } = await this._resolveAndValidateAttestedResource(
        agentContext,
        revocationRegistryId,
        'revocation status list',
        zWebVhRevRegDefContent
      )
      if (!resourceObject.links) {
        throw new CredoError('No revocation entries found.')
      }

      const revocationEntries = resourceObject.links
        .filter(
          (entry): entry is WebVhAttestedResourceLink & { timestamp: number } => typeof entry.timestamp === 'number'
        )
        .sort((a, b) => a.timestamp - b.timestamp)
      if (revocationEntries.length === 0) {
        throw new CredoError('No revocation entries found.')
      }

      // The status list in force at a timestamp is the latest one published at or before it.
      const selectedEntry = revocationEntries.filter((entry) => entry.timestamp <= timestamp).pop()
      if (!selectedEntry) {
        throw new CredoError(`No revocation status list was published at or before timestamp ${timestamp}.`)
      }

      const {
        resourceObject: revocationEntryResourceObject,
        content: statusListContent,
        resolutionResult: revocationEntryResolutionResult,
      } = await this._resolveAndValidateAttestedResource(
        agentContext,
        selectedEntry.id,
        'revocation status list entry',
        zWebVhStatusListContent
      )

      return {
        // The signed status list has no timestamp, so it comes from the link that selected the entry.
        revocationStatusList: { ...statusListContent, timestamp: selectedEntry.timestamp },
        resolutionMetadata: revocationEntryResolutionResult.dereferencingMetadata || {},
        revocationStatusListMetadata: revocationEntryResourceObject.metadata || {},
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error retrieving revocation registry status list '${revocationRegistryId}' via did:webvh`,
        {
          error: error instanceof Error ? error.message : String(error),
          revocationRegistryId,
          timestamp,
        }
      )

      return {
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve revocation registry status list: ${error.message}`,
        },
        revocationStatusListMetadata: {},
      }
    }
  }

  public async registerSchema(
    agentContext: AgentContext,
    options?: WebVhRegisterSchemaOptions
  ): Promise<RegisterSchemaReturn> {
    if (!options?.schema) throw new CredoError('Schema options must be provided.')

    const resourceId = this._digestMultibase(canonicalize(options.schema))
    const schemaId = `${options.schema.issuerId}/resources/${resourceId}`

    const attestedResource = await this.buildSignedResource(agentContext, {
      content: options.schema,
      id: schemaId,
      metadata: {
        resourceId,
        resourceType: 'anonCredsSchema',
        resourceName: options.schema.name,
        ...options.options?.extraMetadata,
      },
      issuerId: options.schema.issuerId,
      verificationMethod: options?.options?.verificationMethod,
    })

    return {
      schemaState: { state: 'finished', schema: options.schema, schemaId },
      registrationMetadata: { attestedResource },
      schemaMetadata: {},
    }
  }

  public async registerCredentialDefinition(
    agentContext: AgentContext,
    options?: WebVhRegisterCredentialDefinitionOptions
  ): Promise<RegisterCredentialDefinitionReturn> {
    if (!options?.credentialDefinition) throw new CredoError('credentialDefinition options must be provided.')

    const resourceId = this._digestMultibase(canonicalize(options.credentialDefinition))

    const credentialDefinitionId = `${options.credentialDefinition.issuerId}/resources/${resourceId}`

    const attestedResource = await this.buildSignedResource(agentContext, {
      content: options.credentialDefinition,
      id: credentialDefinitionId,
      metadata: {
        resourceId,
        resourceType: 'anonCredsCredDef',
        resourceName: options.credentialDefinition.tag,
        ...options.options?.extraMetadata,
      },
      issuerId: options.credentialDefinition.issuerId,
      verificationMethod: options.options?.verificationMethod,
    })

    return {
      credentialDefinitionState: {
        state: 'finished',
        credentialDefinition: options.credentialDefinition,
        credentialDefinitionId,
      },
      credentialDefinitionMetadata: {},
      registrationMetadata: { attestedResource },
    }
  }

  public async registerRevocationRegistryDefinition(
    agentContext: AgentContext,
    options?: WebVhRegisterRevocationRegistryDefinitionOptions
  ): Promise<RegisterRevocationRegistryDefinitionReturn> {
    if (!options?.revocationRegistryDefinition)
      throw new CredoError('revocationRegistryDefinition options must be provided.')

    const resourceId = this._digestMultibase(canonicalize(options.revocationRegistryDefinition))

    const revocationRegistryDefinitionId = `${options.revocationRegistryDefinition.issuerId}/resources/${resourceId}`

    const attestedResource = await this.buildSignedResource(agentContext, {
      content: options.revocationRegistryDefinition,
      id: revocationRegistryDefinitionId,
      metadata: {
        resourceId,
        resourceType: 'anonCredsRevocRegDef',
        resourceName: options.revocationRegistryDefinition.tag,
        ...options.options?.extraMetadata,
      },
      issuerId: options.revocationRegistryDefinition.issuerId,
      verificationMethod: options.options?.verificationMethod,
    })

    return {
      revocationRegistryDefinitionState: {
        state: 'finished',
        revocationRegistryDefinition: options.revocationRegistryDefinition,
        revocationRegistryDefinitionId,
      },
      registrationMetadata: { attestedResource },
      revocationRegistryDefinitionMetadata: {},
    }
  }

  public async updateRevocationRegistryDefinition(
    agentContext: AgentContext,
    registrationMetadata: { proof?: Proof } & Record<string, object>,
    extraInfo: Record<string, object>
  ) {
    const { proof, ...restMetadata } = registrationMetadata

    const vm = proof?.verificationMethod
    if (!vm) throw new CredoError('verificationMethod not found in proof')
    const previousVerificationMethod = typeof vm === 'string' ? vm : vm.id

    // Re-select an authorized verification method rather than reusing the one from the previous
    // proof, which may never have been authorized for the proof purpose in the first place.
    const issuerId = parseDid(previousVerificationMethod).did
    const verificationMethod = await this.getVerificationMethodId(agentContext, issuerId)

    const updatedMetadata = { ...restMetadata, ...extraInfo }

    const newProof = await this.createProof(agentContext, updatedMetadata, verificationMethod)

    return {
      registrationMetadata: {
        ...updatedMetadata,
        proof: newProof,
      },
    }
  }

  public async registerRevocationStatusList(
    agentContext: AgentContext,
    options?: WebVhRegisterRevocationStatusListOptions
  ): Promise<RegisterRevocationStatusListReturn> {
    if (!options?.revocationStatusList) throw new CredoError('revocationStatusList options must be provided.')

    const timestamp = Math.floor(Date.now() / 1000)
    const resourceId = this._digestMultibase(canonicalize(options.revocationStatusList))

    const resourceStatusListId = `${options.revocationStatusList.issuerId}/resources/${resourceId}`

    const attestedResource = await this.buildSignedResource(agentContext, {
      content: options.revocationStatusList,
      id: resourceStatusListId,
      metadata: {
        resourceId,
        resourceType: 'anonCredsStatusList',
        resourceName: '0',
        ...options.options?.extraMetadata,
      },
      issuerId: options.revocationStatusList.issuerId,
      verificationMethod: options?.options?.verificationMethod,
    })

    return {
      revocationStatusListState: {
        state: 'finished',
        revocationStatusList: { ...options.revocationStatusList, timestamp },
      },
      registrationMetadata: { attestedResource },
      revocationStatusListMetadata: {
        previousVersionId: '',
        nextVersionId: '',
      },
    }
  }

  public async verifyProof(agentContext: AgentContext, attestedResource: WebVhAttestedResourceInput): Promise<boolean> {
    const dataIntegrity = agentContext.dependencyManager.resolve(W3cDataIntegrityApi)
    try {
      const verificationResult = await dataIntegrity.verifyProof(
        {
          ...attestedResource,
        } as W3cDataIntegritySingleProofSecuredDocument,
        { expectedProofPurpose: ATTESTED_RESOURCE_PROOF_PURPOSE }
      )

      if (!verificationResult.verified) {
        agentContext.config.logger.error('Proof validation of did:webvh resource failed', {
          resourceId: attestedResource.id,
          verificationMethod: attestedResource.proof?.verificationMethod,
          errors: verificationResult.errors,
        })
        return false
      }

      // Other cryptosuites can be registered with the agent, but are not allowed for attested resources
      if (attestedResource.proof.cryptosuite !== ATTESTED_RESOURCE_CRYPTOSUITE) {
        agentContext.config.logger.error('Proof of did:webvh resource uses an unsupported cryptosuite', {
          resourceId: attestedResource.id,
          cryptosuite: attestedResource.proof.cryptosuite,
        })
        return false
      }

      return true
    } catch (error) {
      agentContext.config.logger.error('Error during proof validation of did:webvh resource', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      })
      return false
    }
  }

  public async createProof(
    agentContext: AgentContext,
    unsecuredDocument: W3cDataIntegrityUnsecuredDocument,
    verificationMethod: string
  ) {
    const dataIntegrity = agentContext.dependencyManager.resolve(W3cDataIntegrityApi)
    try {
      const creationResult = await dataIntegrity.createProofOrThrow({
        unsecuredDocument,
        cryptosuite: ATTESTED_RESOURCE_CRYPTOSUITE,
        verificationMethod,
        proofPurpose: ATTESTED_RESOURCE_PROOF_PURPOSE,
      })
      return creationResult.proof
    } catch (error) {
      agentContext.config.logger.error('Error during proof creation of did:webvh resource', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      })
      throw error
    }
  }

  private async buildSignedResource(
    agentContext: AgentContext,
    {
      content,
      id,
      metadata,
      issuerId,
      verificationMethod,
    }: {
      content:
        | AnonCredsSchema
        | AnonCredsCredentialDefinition
        | AnonCredsRevocationRegistryDefinition
        | AnonCredsRevocationStatusListWithoutTimestamp
      id: string
      metadata: Record<string, unknown>
      issuerId: string
      verificationMethod?: string
    }
  ) {
    const verificationMethodId = await this.getVerificationMethodId(agentContext, issuerId, verificationMethod)

    // Prepare the generic resource payload to be signed
    const resourcePayload = {
      '@context': [
        'https://identity.foundation/did-attested-resources/context/v0.1',
        'https://w3id.org/security/data-integrity/v2',
      ],
      type: ['AttestedResource'],
      id,
      content,
      metadata,
    }

    const proof = await this.createProof(agentContext, resourcePayload, verificationMethodId)
    return {
      ...resourcePayload,
      proof,
    }
  }

  private async getVerificationMethodId(
    agentContext: AgentContext,
    issuerId: string,
    explicitVerificationMethod?: string
  ): Promise<string> {
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)

    const didRecord = await didRepository.findCreatedDid(agentContext, issuerId)
    if (!didRecord) {
      throw new CredoError(`No DID found for issuer ${issuerId}`)
    }

    const didDocument = didRecord.didDocument
    if (!didDocument) {
      throw new CredoError(`No did document stored on the did record for issuer ${issuerId}`)
    }

    // Relative references ('#key-1') are valid within a did document, but a proof's
    // verificationMethod must resolve on its own, so we always return an absolute did url.
    const toAbsoluteId = (id: string) => (id.startsWith('#') ? `${didDocument.id}${id}` : id)

    // Multikey and JsonWebKey2020 can hold any key type, so check the key itself: eddsa-jcs-2022
    // can only sign with Ed25519.
    const isEd25519 = (method: VerificationMethod) => {
      try {
        return getPublicJwkFromVerificationMethod(method).is(Kms.Ed25519PublicJwk)
      } catch {
        return false
      }
    }

    if (explicitVerificationMethod) {
      let method: VerificationMethod
      try {
        method = didDocument.dereferenceKey(explicitVerificationMethod, [ATTESTED_RESOURCE_PROOF_PURPOSE])
      } catch (error) {
        throw new CredoError(
          `Verification method '${explicitVerificationMethod}' is not authorized for '${ATTESTED_RESOURCE_PROOF_PURPOSE}' in the did document of issuer ${issuerId}`,
          { cause: error }
        )
      }

      if (!isEd25519(method)) {
        throw new CredoError(
          `Verification method '${explicitVerificationMethod}' is not an Ed25519 key, which '${ATTESTED_RESOURCE_CRYPTOSUITE}' requires`
        )
      }

      return toAbsoluteId(method.id)
    }

    const authorizedMethods = didDocument
      .findVerificationMethodsByTypeAndPurpose(keyDidEd25519.supportedVerificationMethodTypes, [
        ATTESTED_RESOURCE_PROOF_PURPOSE,
      ])
      .filter(isEd25519)
      .sort((a, b) => Number(b.type === 'Multikey') - Number(a.type === 'Multikey'))
    const authorizedIds = authorizedMethods.map((method) => toAbsoluteId(method.id))

    if (authorizedIds.length === 0) {
      throw new CredoError(
        `No Ed25519 verification method authorized for '${ATTESTED_RESOURCE_PROOF_PURPOSE}' found in the did document of issuer ${issuerId}`
      )
    }

    // Prefer a verification method this agent holds the key for. Did records created before keys
    // were tracked have none, and signing those still resolves the key id from the public key, so
    // the first authorized method remains the fallback rather than an error.
    return (
      authorizedIds.find((id) => didRecord.keys?.some((key) => id.endsWith(key.didDocumentRelativeKeyId))) ??
      authorizedIds[0]
    )
  }
}

export type WebVhRegisterSchemaOptions = Omit<RegisterSchemaOptions, 'options'> & {
  options?: {
    verificationMethod?: string
    extraMetadata?: Record<string, unknown>
  }
}

export type WebVhRegisterCredentialDefinitionOptions = Omit<RegisterCredentialDefinitionOptions, 'options'> & {
  options?: {
    verificationMethod?: string
    extraMetadata?: Record<string, unknown>
  }
}

export type WebVhRegisterRevocationRegistryDefinitionOptions = Omit<
  RegisterRevocationRegistryDefinitionOptions,
  'options'
> & {
  options?: {
    verificationMethod?: string
    extraMetadata?: Record<string, unknown>
  }
}

export type WebVhRegisterRevocationStatusListOptions = Omit<RegisterRevocationStatusListOptions, 'options'> & {
  options?: {
    verificationMethod?: string
    extraMetadata?: Record<string, unknown>
  }
}
