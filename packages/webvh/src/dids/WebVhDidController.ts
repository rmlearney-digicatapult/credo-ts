import {
  type AgentContext,
  CredoError,
  type DidCreateResult,
  DidDocument,
  type DidDocumentKey,
  DidDocumentRole,
  type DidRecord,
  DidRepository,
  getPublicJwkFromVerificationMethod,
  Kms,
  parseDid,
  type VerificationMethod,
} from '@credo-ts/core'
import {
  type DIDLog,
  type DIDResolutionMeta,
  parseDidWebvh,
  type Signer,
  type UpdateDIDOptions,
  type UpdateDIDResult,
  type WitnessProofFileEntry,
} from 'didwebvh-ts'

import { WebVhDidCrypto } from './WebVhDidCrypto'
import { WebVhDidCryptoSigner } from './WebVhDidCryptoSigner'
import { WebVhDidRecordMetadataKeys, type WebVhUpdateKeyKmsKeyIds } from './webVhTypes'

export function getWebVhDomainTag(did: string) {
  const { domainComponent, pathSegments } = parseDidWebvh(did)
  return [domainComponent, ...pathSegments.map((segment) => encodeURIComponent(segment))].join(':')
}

export async function getWebVhDidRecord(agentContext: AgentContext, did: string) {
  const record = await agentContext.dependencyManager.resolve(DidRepository).findSingleByQuery(agentContext, {
    role: DidDocumentRole.Created,
    did,
    method: 'webvh',
  })
  if (!record) throw new CredoError(`notFound: controlled WebVH DID '${did}' not found`)
  return record
}

export function getWebVhDidLog(record: DidRecord) {
  const log = record.metadata.get<DIDLog>(WebVhDidRecordMetadataKeys.DidLog)
  if (!log?.length) throw new CredoError(`unknownError: controlled DID '${record.did}' has no persisted log`)
  return log
}

export function getWebVhControllerMetadata(record: DidRecord): DIDResolutionMeta {
  const metadata = record.metadata.get<DIDResolutionMeta>(WebVhDidRecordMetadataKeys.ControllerMetadata)
  if (!metadata) {
    throw new CredoError(`unknownError: controlled DID '${record.did}' has no persisted controller metadata`)
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
  if (!(didDocument instanceof DidDocument) || !didDocument.id) {
    throw new CredoError('notSupported: WebVH requires a complete DidDocument with an id')
  }
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
  const writerOptions: UpdateDIDOptions = {
    ...upstreamOptions,
    log: getWebVhDidLog(record),
    didDocument: { ...didDocument.toJSON(), id: didDocument.id },
    witnessProofs:
      input.witnessProofs ??
      record.metadata.get<WitnessProofFileEntry[]>(WebVhDidRecordMetadataKeys.WitnessProofs) ??
      undefined,
    signer,
    verifier: new WebVhDidCrypto(agentContext),
    fetch: agentContext.config.fetch.bind(agentContext.config),
  }
  return { record, controllerKeys, keys: validatedKeys, writerOptions }
}

export async function persistWebVhDocumentWrite(
  agentContext: AgentContext,
  prepared: Awaited<ReturnType<typeof prepareWebVhDocumentWrite>>,
  result: UpdateDIDResult
) {
  const { record, controllerKeys, writerOptions } = prepared
  const domain = getWebVhDomainTag(result.did)
  const didDocument = DidDocument.fromJSON(result.doc)
  const keys = await validateWebVhDocumentKeys(
    agentContext,
    didDocument,
    prepared.keys ?? retainWebVhDocumentKeys(record.didDocument, didDocument, record.keys ?? [])
  )
  record.setTags({ domain })
  record.did = result.did
  record.didDocument = didDocument
  record.keys = keys
  record.metadata.set(WebVhDidRecordMetadataKeys.DidLog, result.log)
  record.metadata.set(WebVhDidRecordMetadataKeys.ControllerMetadata, result.meta)
  record.metadata.set(WebVhDidRecordMetadataKeys.UpdateKeyKmsKeyIds, controllerKeys)
  if (writerOptions.witnessProofs)
    record.metadata.set(WebVhDidRecordMetadataKeys.WitnessProofs, writerOptions.witnessProofs)
  await agentContext.dependencyManager.resolve(DidRepository).update(agentContext, record)
  return didDocument
}

export function failedWebVhRegistration(
  agentContext: AgentContext,
  operation: string,
  error: unknown
): DidCreateResult {
  agentContext.config.logger.error(`WebVH ${operation} failed`, { error })
  const message = error instanceof Error ? error.message : String(error)
  const reason =
    error instanceof Kms.KeyManagementKeyNotFoundError
      ? `notFound: ${message}`
      : /^(notFound|notSupported|unknownError):/.test(message)
        ? message
        : `unknownError: ${message}`
  return {
    didDocumentMetadata: {},
    didRegistrationMetadata: {},
    didState: { state: 'failed', reason },
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
      throw new CredoError('unknownError: no authorized controller update keys remain to sign this operation')
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
    throw new CredoError('unknownError: no authorized controller update key has a Credo KMS mapping')
  }
  return {
    getVerificationMethodId: () => getSigner().getVerificationMethodId(),
    sign: (input) => getSigner().sign(input),
  }
}

function tryDereferenceDocumentKey(document: DidDocument, relativeId: string): VerificationMethod | undefined {
  try {
    return document.dereferenceKey(relativeId)
  } catch (error) {
    if (
      error instanceof CredoError &&
      error.message.startsWith(`Unable to locate verification method with id '${relativeId}' in purposes `)
    ) {
      return undefined
    }
    throw error
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

export function retainWebVhDocumentKeys(
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
