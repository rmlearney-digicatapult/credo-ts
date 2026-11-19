import {
  AgentContext,
  CredoError,
  DidDocument,
  type DidDocumentKey,
  DidRepository,
  DidResolverService,
  type DidUpdateResult,
  injectable,
  type Kms,
} from '@credo-ts/core'
import {
  type DIDDocument,
  type DIDLog,
  deriveNextKeyHash,
  fetchWitnessProofs,
  getWitnessRequirements,
  type MigrateDIDOptions,
  migrateDID,
  type ResolutionOptions,
  resolveDIDFromLog,
  signWitnessProofEntry,
  type VerifyWitnessProofsOptions,
  verifyWitnessProofs,
  type WitnessProofFileEntry,
  type WitnessRequirement,
  type WitnessSigningOptions,
  type WitnessVerificationResult,
} from 'didwebvh-ts'

import { getWebVhDidResolver } from './dids/getWebVhDidResolver'
import {
  createWebVhWitnessSigner,
  failedWebVhRegistration,
  getStoredWitnessProofs,
  getWebVhDidLog,
  getWebVhDidRecord,
  getWebVhFetch,
  persistWebVhDocumentWrite,
  prepareWebVhDocumentWrite,
} from './dids/WebVhDidController'
import { WebVhDidRecordMetadataKeys, type WebVhUpdateKeyKmsKeyIds } from './dids/webVhTypes'

export type WebVhWitnessSigningOptions = Pick<
  WitnessSigningOptions,
  'trustedLog' | 'candidateLog' | 'witnessProofs'
> & {
  kmsKeyId: string
  kmsBackend?: string
}

export type WebVhWitnessVerificationOptions = Omit<VerifyWitnessProofsOptions, 'verifier'>
export type WebVhLogResolutionOptions = Omit<ResolutionOptions, 'verifier' | 'fetch' | 'resolveControlledDid'>

export interface WebVhDidMigrateOptions {
  did: string
  didDocument: DidDocument
  options: Omit<MigrateDIDOptions, 'didDocument' | 'signer' | 'verifier' | 'fetch' | 'log'> & {
    keys?: DidDocumentKey[]
    updateKeyKmsKeyIds?: WebVhUpdateKeyKmsKeyIds
  }
}

@injectable()
export class WebVhApi {
  private agentContext: AgentContext

  public constructor(agentContext: AgentContext) {
    this.agentContext = agentContext
  }

  /**
   * Dereferences a WebVH resource using the agent's configured fetch limits.
   *
   * @param resourceUrl WebVH DID URL identifying the resource.
   * @returns Resource content and dereferencing metadata, or an explicit resolution error.
   */
  public async resolveResource(resourceUrl: string) {
    const webvhDidResolver = getWebVhDidResolver(this.agentContext)
    return await webvhDidResolver.resolveResource(this.agentContext, resourceUrl)
  }

  /**
   * Returns detached copies of the stored log, witness-proof file and parallel did:web document for caller-managed
   * publication.
   *
   * @param did Controlled WebVH DID.
   * @returns Stored log and witness proofs, with an empty proof array when none are stored, and `webDoc` for `did.json`
   * when didwebvh-ts returned one from the latest write.
   */
  public async getPublicationData(did: string) {
    try {
      const record = await getWebVhDidRecord(this.agentContext, did)
      const webDoc = record.metadata.get<DIDDocument>(WebVhDidRecordMetadataKeys.ParallelDidWebDocument)
      return structuredClone({
        log: getWebVhDidLog(record),
        witnessProofs: getStoredWitnessProofs(record) ?? [],
        ...(webDoc && { webDoc }),
      })
    } catch (error) {
      throw new CredoError(`Unable to retrieve WebVH publication data for '${did}'`, { cause: error })
    }
  }

  /**
   * Validates a supplied log without reading local records or publishing it. When the log requires witness approvals
   * and `witnessProofs` is omitted, the published witness-proof file is fetched.
   *
   * @param log DID log to validate, such as a log returned by getPublicationData.
   * @param options Upstream version selectors and optional witness-proof file.
   * @returns Resolved Credo document and upstream metadata, including any validation error.
   */
  public async resolveDIDFromLog(log: DIDLog, options: WebVhLogResolutionOptions = {}) {
    try {
      const result = await resolveDIDFromLog(log, {
        ...options,
        fetch: getWebVhFetch(this.agentContext),
      })
      return {
        didDocument: result.didDocument ? DidDocument.fromJSON(result.didDocument) : null,
        didDocumentMetadata: result.didDocumentMetadata,
        didResolutionMetadata: result.didResolutionMetadata,
      }
    } catch (error) {
      throw new CredoError('Unable to resolve WebVH DID from log', { cause: error })
    }
  }

  /**
   * Replaces the entire stored witness-proof file without modifying the log or contacting witnesses.
   * Include proofs for earlier log entries that remain required; an empty array clears the file.
   *
   * @param did Controlled WebVH DID.
   * @param witnessProofs Complete replacement witness-proof file.
   * @returns A promise resolving when the replacement is persisted.
   */
  public async storeWitnessProofs(did: string, witnessProofs: WitnessProofFileEntry[]) {
    try {
      const record = await getWebVhDidRecord(this.agentContext, did)
      if (!Array.isArray(witnessProofs)) throw new CredoError('witnessProofs must be an array')
      record.metadata.set(WebVhDidRecordMetadataKeys.WitnessProofs, structuredClone(witnessProofs))
      await this.agentContext.dependencyManager.resolve(DidRepository).update(this.agentContext, record)
    } catch (error) {
      throw new CredoError(`Unable to store WebVH witness proofs for '${did}'`, { cause: error })
    }
  }

  /**
   * Lists the governing witnesses and threshold for each log entry that needs witnessing, without verifying signatures.
   *
   * @param log DID log to inspect, such as a candidate log returned by a write.
   * @returns One requirement per entry that needs witnessing.
   */
  public getWitnessRequirements(log: DIDLog): WitnessRequirement[] {
    try {
      return getWitnessRequirements(log)
    } catch (error) {
      throw new CredoError('Unable to derive WebVH witness requirements', { cause: error })
    }
  }

  /**
   * Returns the witnesses that must approve the latest entry of the stored log, and how many of them must.
   *
   * @param did Controlled WebVH DID.
   * @returns The requirement for the latest entry, or undefined when it needs no approvals.
   */
  public async getWitnessRequirement(did: string): Promise<WitnessRequirement | undefined> {
    try {
      const log = getWebVhDidLog(await getWebVhDidRecord(this.agentContext, did))
      // Requirements follow the order of the log, so only the last one can be for the latest entry.
      const requirement = getWitnessRequirements(log).at(-1)
      return requirement?.versionId === log[log.length - 1].versionId ? requirement : undefined
    } catch (error) {
      throw new CredoError(`Unable to derive the WebVH witness requirement for '${did}'`, { cause: error })
    }
  }

  /**
   * Verifies supplied proofs locally without fetching, storing, or publishing them.
   *
   * @param options DID log and complete witness-proof file.
   * @returns Per-entry approvals, threshold satisfaction, and rejected-proof details.
   */
  public async verifyWitnessProofs(options: WebVhWitnessVerificationOptions): Promise<WitnessVerificationResult> {
    try {
      return await verifyWitnessProofs(options)
    } catch (error) {
      throw new CredoError('Unable to verify WebVH witness proofs', { cause: error })
    }
  }

  /**
   * Fetches the published witness-proof file using the agent's configured fetch without storing it.
   *
   * @param did WebVH DID whose published proofs should be fetched.
   * @returns Published proofs, or an empty array when upstream reports HTTP 404.
   */
  public async fetchWitnessProofs(did: string): Promise<WitnessProofFileEntry[]> {
    try {
      return await fetchWitnessProofs(did, getWebVhFetch(this.agentContext))
    } catch (error) {
      throw new CredoError(`Unable to fetch WebVH witness proofs for '${did}'`, { cause: error })
    }
  }

  /**
   * Derives the pre-rotation hash of a future update key, to list in `nextKeyHashes`.
   *
   * @param publicJwk Ed25519 key that may sign the DID log after the next rotation, such as one from `PublicJwk.fromKmsKey`.
   * @returns The hash that commits the DID to the key.
   */
  public async deriveNextKeyHash(publicJwk: Kms.PublicJwk): Promise<string> {
    try {
      return await deriveNextKeyHash(publicJwk.fingerprint)
    } catch (error) {
      throw new CredoError('Unable to derive the WebVH next key hash', { cause: error })
    }
  }

  /**
   * Migrates an existing portable percent-encoded U-label DID to A-label form and persists the returned document and log.
   *
   * @param options Complete replacement document, existing U-label address, and optional KMS mappings.
   * @returns Finished migration or a failed registration; publication remains caller-managed.
   */
  public async migrate(options: WebVhDidMigrateOptions): Promise<DidUpdateResult> {
    try {
      // Migration bypasses DidsApi.update, which evicts the cached document before writing.
      await this.agentContext.dependencyManager
        .resolve(DidResolverService)
        .invalidateCacheForDid(this.agentContext, options.did)
      const prepared = await prepareWebVhDocumentWrite(
        this.agentContext,
        options.did,
        options.didDocument,
        options.options
      )
      const result = await migrateDID({ ...prepared.writerOptions, address: options.options.address })
      const didDocument = await persistWebVhDocumentWrite(this.agentContext, prepared, result)
      return {
        didDocumentMetadata: result.meta,
        didRegistrationMetadata: {},
        didState: { state: 'finished', did: result.did, didDocument },
      }
    } catch (error) {
      return failedWebVhRegistration(this.agentContext, 'migrate', error)
    }
  }

  /**
   * Validates and signs a candidate log with an existing witness KMS key without storing or publishing the proof.
   *
   * @param options Trusted and candidate logs, optional witness proofs, and the witness KMS key id.
   * @returns Signed witness-proof entry for caller-managed collection and publication.
   */
  public async signWitnessProof(options: WebVhWitnessSigningOptions): Promise<WitnessProofFileEntry> {
    try {
      const witnessSigner = await createWebVhWitnessSigner(this.agentContext, {
        keyId: options.kmsKeyId,
        kmsBackend: options.kmsBackend,
      })
      return await signWitnessProofEntry({
        trustedLog: options.trustedLog,
        candidateLog: options.candidateLog,
        witnessProofs: options.witnessProofs,
        witnessSigner,
      })
    } catch (error) {
      throw new CredoError(`Unable to sign WebVH witness proof with KMS key '${options.kmsKeyId}'`, { cause: error })
    }
  }
}
