import {
  type AgentContext,
  CredoError,
  type DidCreateResult,
  DidDocument,
  type DidDocumentKey,
  DidDocumentRole,
  DidRecord,
  DidRepository,
  DidResolverService,
  DidsApi,
  getPublicJwkFromVerificationMethod,
  Kms,
  parseDid,
  type VerificationMethod,
} from '@credo-ts/core'
import {
  type DIDDocument,
  type DIDLog,
  type DIDResolutionMeta,
  defaultVerifier,
  parseDidWebvh,
  type Signer,
  type UpdateDIDOptions,
  type UpdateDIDResult,
  type WitnessProofFileEntry,
} from 'didwebvh-ts'

import { WebVhDidCryptoSigner } from './WebVhDidCryptoSigner'
import { WebVhDidRecordMetadataKeys, type WebVhUpdateKeyKmsKeyIds } from './webVhTypes'

export function getWebVhDomainTag(did: string) {
  const { scid } = parseDidWebvh(did)
  // Re-encoding decoded segments could differ from the DID's canonical encoding, so keep the DID's own text.
  return did.slice(`did:webvh:${scid}:`.length)
}

/**
 * Carries the DID registration failure reason that `failedWebVhRegistration` reports before the message.
 */
export class WebVhRegistrationError extends CredoError {
  public readonly reason: 'notFound' | 'notSupported'

  public constructor(reason: 'notFound' | 'notSupported', message: string) {
    super(message)
    this.reason = reason
  }
}

export function assertWebVhDidDocument(document: DidDocument) {
  if (!(document instanceof DidDocument) || !document.id) {
    throw new WebVhRegistrationError('notSupported', 'WebVH requires a complete DidDocument with an id')
  }
}

export async function getWebVhDidRecord(agentContext: AgentContext, did: string) {
  const record = await agentContext.dependencyManager.resolve(DidRepository).findSingleByQuery(agentContext, {
    role: DidDocumentRole.Created,
    did,
    method: 'webvh',
  })
  if (!record) throw new WebVhRegistrationError('notFound', `controlled WebVH DID '${did}' not found`)
  return record
}

export function getWebVhDidLog(record: DidRecord) {
  const log = record.metadata.get<DIDLog>(WebVhDidRecordMetadataKeys.DidLog)
  if (!log?.length) throw new CredoError(`controlled DID '${record.did}' has no persisted log`)
  return log
}

export function getWebVhControllerMetadata(record: DidRecord): DIDResolutionMeta {
  const metadata = record.metadata.get<DIDResolutionMeta>(WebVhDidRecordMetadataKeys.ControllerMetadata)
  if (!metadata) {
    throw new CredoError(`controlled DID '${record.did}' has no persisted controller metadata`)
  }
  return metadata
}

export async function prepareWebVhDocumentWrite(
  agentContext: AgentContext,
  did: string,
  didDocument: DidDocument,
  input: Omit<UpdateDIDOptions, 'didDocument' | 'signer' | 'verifier' | 'fetch' | 'log'> & {
    keys?: DidDocumentKey[]
    updateKeyKmsKeyIds?: WebVhUpdateKeyKmsKeyIds
  }
) {
  assertWebVhDidDocument(didDocument)
  const record = await getWebVhDidRecord(agentContext, did)
  const { keys, updateKeyKmsKeyIds, ...upstreamOptions } = input
  const state = getWebVhControllerMetadata(record)
  const validatedControllerKeys = updateKeyKmsKeyIds
    ? await validateWebVhControllerKeys(agentContext, updateKeyKmsKeyIds)
    : undefined
  const controllerKeys = {
    ...record.metadata.get<WebVhUpdateKeyKmsKeyIds>(WebVhDidRecordMetadataKeys.UpdateKeyKmsKeyIds),
    ...validatedControllerKeys,
  }
  const validatedKeys = keys ? await validateWebVhDocumentKeys(agentContext, didDocument, keys) : undefined
  const signer = createWebVhControllerSigner(
    agentContext,
    state.prerotation ? input.updateKeys : state.updateKeys,
    controllerKeys
  )
  const witnessProofs =
    input.witnessProofs ??
    record.metadata.get<WitnessProofFileEntry[]>(WebVhDidRecordMetadataKeys.WitnessProofs) ??
    undefined
  const writerOptions: UpdateDIDOptions = {
    ...upstreamOptions,
    log: getWebVhDidLog(record),
    didDocument: { ...didDocument.toJSON(), id: didDocument.id },
    witnessProofs,
    signer,
    // didwebvh-ts only defaults the verifier when resolving, not when writing.
    verifier: defaultVerifier,
    fetch: agentContext.config.fetch.bind(agentContext.config),
  }
  return { record, controllerKeys, keys: validatedKeys, witnessProofs, writerOptions }
}

export interface WebVhDocumentWrite {
  /** Record to update. A new record is saved when omitted. */
  record?: DidRecord
  controllerKeys: WebVhUpdateKeyKmsKeyIds
  /** Document keys already checked against the KMS. When omitted, mappings whose public key is unchanged are kept. */
  keys?: DidDocumentKey[]
  witnessProofs?: WitnessProofFileEntry[]
}

/**
 * Stores the DID, document, log and metadata that didwebvh-ts returned, then imports its parallel did:web.
 */
export async function persistWebVhDocumentWrite(
  agentContext: AgentContext,
  write: WebVhDocumentWrite,
  result: UpdateDIDResult
) {
  const { controllerKeys, witnessProofs } = write
  await assertParallelDidWebAvailable(agentContext, result.did, result.webDoc, write.record?.id)
  const record = write.record ?? new DidRecord({ did: result.did, role: DidDocumentRole.Created })
  const previousParallelDidWebDocument =
    record.metadata.get<DIDDocument>(WebVhDidRecordMetadataKeys.ParallelDidWebDocument) ?? undefined
  const webVhDidDocument = DidDocument.fromJSON(result.doc)
  const keys = write.keys ?? retainWebVhDocumentKeys(record.didDocument, webVhDidDocument, record.keys ?? [])
  record.setTags({ domain: getWebVhDomainTag(result.did) })
  record.did = result.did
  record.didDocument = webVhDidDocument
  record.keys = keys
  record.metadata.set(WebVhDidRecordMetadataKeys.DidLog, result.log)
  record.metadata.set(WebVhDidRecordMetadataKeys.ControllerMetadata, result.meta)
  record.metadata.set(WebVhDidRecordMetadataKeys.UpdateKeyKmsKeyIds, controllerKeys)
  if (witnessProofs) record.metadata.set(WebVhDidRecordMetadataKeys.WitnessProofs, witnessProofs)
  setParallelDidWebDocument(record, result.webDoc)
  const repository = agentContext.dependencyManager.resolve(DidRepository)
  if (write.record) await repository.update(agentContext, record)
  else await repository.save(agentContext, record)
  await syncParallelDidWebRecord(agentContext, result.did, previousParallelDidWebDocument, result.webDoc, keys)
  return webVhDidDocument
}

/**
 * Stores the parallel did:web document from the latest write, or clears it when didwebvh-ts returned none.
 */
function setParallelDidWebDocument(record: DidRecord, document: DIDDocument | undefined) {
  if (document) record.metadata.set(WebVhDidRecordMetadataKeys.ParallelDidWebDocument, document)
  else record.metadata.delete(WebVhDidRecordMetadataKeys.ParallelDidWebDocument)
}

/**
 * Fails when another did:webvh at the same location already provides this parallel did:web, as only one `did.json`
 * can be published there.
 */
async function assertParallelDidWebAvailable(
  agentContext: AgentContext,
  webVhDid: string,
  parallelDidWebDocument: DIDDocument | undefined,
  webVhRecordId?: string
) {
  if (!parallelDidWebDocument) return
  const webVhRecordsAtLocation = await agentContext.dependencyManager
    .resolve(DidRepository)
    .findByQuery(agentContext, { role: DidDocumentRole.Created, method: 'webvh', domain: getWebVhDomainTag(webVhDid) })
  const owningWebVhRecord = webVhRecordsAtLocation.find(
    (record) =>
      record.id !== webVhRecordId &&
      record.metadata.get<DIDDocument>(WebVhDidRecordMetadataKeys.ParallelDidWebDocument)?.id ===
        parallelDidWebDocument.id
  )
  if (owningWebVhRecord) {
    throw new CredoError(
      `The parallel did:web '${parallelDidWebDocument.id}' already belongs to did:webvh '${owningWebVhRecord.did}'`
    )
  }
}

/**
 * Imports the parallel did:web document with the did:webvh document keys, so the agent can resolve and sign as the
 * did:web, and clears the resolver cache of the previous and new did:web.
 */
async function syncParallelDidWebRecord(
  agentContext: AgentContext,
  webVhDid: string,
  previousDocument: DIDDocument | undefined,
  document: DIDDocument | undefined,
  keys: DidDocumentKey[]
) {
  if (!previousDocument && !document) return
  try {
    const didResolverService = agentContext.dependencyManager.resolve(DidResolverService)
    if (previousDocument && previousDocument.id !== document?.id) {
      // TODO: delete the previous did:web record, but not its keys, which the did:webvh still uses, once
      // DidsApi.deleteCreatedDid exists (https://github.com/openwallet-foundation/credo-ts/pull/3289).
      agentContext.config.logger.warn(
        `The did:web record '${previousDocument.id}' is no longer the parallel did:web of '${webVhDid}' and is kept until it can be deleted`
      )
      await didResolverService.invalidateCacheForDid(agentContext, previousDocument.id)
    }
    if (!document) return
    const dids = agentContext.dependencyManager.resolve(DidsApi)
    if (previousDocument?.id !== document.id && (await dids.getCreatedDids({ did: document.id })).length > 0) {
      agentContext.config.logger.warn(
        `Replacing the did:web record '${document.id}' with the parallel did:web of '${webVhDid}'`
      )
    }
    await dids.import({ did: document.id, didDocument: DidDocument.fromJSON(document), keys, overwrite: true })
    await didResolverService.invalidateCacheForDid(agentContext, document.id)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new CredoError(`'${webVhDid}' was stored, but updating its parallel did:web record failed: ${message}`, {
      cause: error,
    })
  }
}

export function failedWebVhRegistration(
  agentContext: AgentContext,
  operation: string,
  error: unknown
): DidCreateResult {
  agentContext.config.logger.error(`WebVH ${operation} failed`, { error })
  const message = error instanceof Error ? error.message : String(error)
  const reason =
    error instanceof WebVhRegistrationError
      ? error.reason
      : error instanceof Kms.KeyManagementKeyNotFoundError
        ? 'notFound'
        : 'unknownError'
  return {
    didDocumentMetadata: {},
    didRegistrationMetadata: {},
    didState: { state: 'failed', reason: `${reason}: ${message}` },
  }
}

export async function getWebVhKmsPublicJwk(
  agentContext: AgentContext,
  keyReference: Kms.KmsKeyReference
): Promise<{ publicJwk: Kms.PublicJwk; kmsBackend: string }> {
  const { publicKey: key, backend } = await agentContext.dependencyManager
    .resolve(Kms.KeyManagementApi)
    .getPublicKey({ keyId: keyReference.keyId, backend: keyReference.kmsBackend })
  if (key.kty === 'oct') throw new CredoError(`KMS key '${keyReference.keyId}' must be asymmetric`)
  return { publicJwk: Kms.PublicJwk.fromPublicJwk(key), kmsBackend: backend }
}

export async function createWebVhKmsSigner(agentContext: AgentContext, keyReference: Kms.KmsKeyReference) {
  const { publicJwk, kmsBackend } = await getWebVhKmsPublicJwk(agentContext, keyReference)
  if (!publicJwk.is(Kms.Ed25519PublicJwk)) {
    throw new CredoError(`KMS key '${keyReference.keyId}' must be Ed25519 to sign a WebVH proof`)
  }
  return new WebVhDidCryptoSigner(agentContext, publicJwk.fingerprint, keyReference.keyId, kmsBackend)
}

export async function validateWebVhControllerKeys(
  agentContext: AgentContext,
  mappings: WebVhUpdateKeyKmsKeyIds
): Promise<WebVhUpdateKeyKmsKeyIds> {
  const validatedMappings: WebVhUpdateKeyKmsKeyIds = {}
  for (const [multikey, keyReference] of Object.entries(mappings)) {
    const resolvedKey = await getWebVhKmsPublicJwk(agentContext, keyReference)
    const { publicJwk, kmsBackend } = resolvedKey
    if (publicJwk.fingerprint !== multikey) {
      throw new CredoError(`Controller update key '${multikey}' does not match KMS key '${keyReference.keyId}'`)
    }
    validatedMappings[multikey] = { keyId: keyReference.keyId, kmsBackend }
  }
  return validatedMappings
}

export function createWebVhControllerSigner(
  agentContext: AgentContext,
  updateKeys: string[] | undefined,
  mappings: WebVhUpdateKeyKmsKeyIds
): Signer {
  let signer: WebVhDidCryptoSigner | undefined
  // Upstream validates the operation before requesting the proof ID; KMS access happens in sign().
  const getSigner = () => {
    if (signer) return signer
    if (!updateKeys?.length) {
      throw new CredoError('no authorized controller update keys remain to sign this operation')
    }
    for (const updateKey of updateKeys) {
      // Upstream accepts did:key inputs but stores bare multikeys in authenticated metadata.
      const multikey = updateKey.startsWith('did:key:') ? parseDid(updateKey).id : updateKey
      const keyReference = mappings[multikey]
      if (keyReference) {
        signer = new WebVhDidCryptoSigner(agentContext, multikey, keyReference.keyId, keyReference.kmsBackend)
        return signer
      }
    }
    throw new CredoError('no authorized controller update key has a Credo KMS mapping')
  }
  return {
    getVerificationMethodId: () => getSigner().getVerificationMethodId(),
    sign: (input) => getSigner().sign(input),
  }
}

function tryDereferenceDocumentKey(document: DidDocument, relativeId: string): VerificationMethod | undefined {
  try {
    return document.dereferenceKey(relativeId)
  } catch {
    // dereferenceKey throws when the key is absent or references a missing method; either way it can't be used.
    return undefined
  }
}

export async function validateWebVhDocumentKeys(
  agentContext: AgentContext,
  document: DidDocument,
  keys: DidDocumentKey[]
): Promise<DidDocumentKey[]> {
  const resolvedKeys: DidDocumentKey[] = []
  for (const { didDocumentRelativeKeyId, kmsKeyId, kmsBackend } of keys) {
    if (!didDocumentRelativeKeyId.startsWith('#') || didDocumentRelativeKeyId.length === 1) {
      throw new CredoError('Document KMS mappings require a caller-authored relative key ID such as #key-1')
    }
    const method = tryDereferenceDocumentKey(document, didDocumentRelativeKeyId)
    if (!method) throw new CredoError(`Document key '${didDocumentRelativeKeyId}' is not present in the DID document`)
    const { publicJwk, kmsBackend: resolvedBackend } = await getWebVhKmsPublicJwk(agentContext, {
      keyId: kmsKeyId,
      kmsBackend,
    })
    if (!getPublicJwkFromVerificationMethod(method).equals(publicJwk)) {
      throw new CredoError(`Document key '${didDocumentRelativeKeyId}' does not match KMS key '${kmsKeyId}'`)
    }
    resolvedKeys.push({ didDocumentRelativeKeyId, kmsKeyId, kmsBackend: resolvedBackend })
  }
  return resolvedKeys
}

function retainWebVhDocumentKeys(
  previousDocument: DidDocument | undefined,
  document: DidDocument,
  keys: DidDocumentKey[]
) {
  return keys.filter(({ didDocumentRelativeKeyId }) => {
    const previous = previousDocument && tryDereferenceDocumentKey(previousDocument, didDocumentRelativeKeyId)
    const next = tryDereferenceDocumentKey(document, didDocumentRelativeKeyId)
    return (
      previous && next && getPublicJwkFromVerificationMethod(previous).equals(getPublicJwkFromVerificationMethod(next))
    )
  })
}
