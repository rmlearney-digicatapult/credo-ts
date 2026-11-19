import type { Kms } from '@credo-ts/core'
import type { DIDLog, DIDLogEntry, WitnessProofFileEntry } from 'didwebvh-ts'

// Keep upstream log and witness proof file types available through the Credo package API.
export type WebVhDidLog = DIDLog
export type WebVhDidLogEntry = DIDLogEntry
/** The approvals of one log entry in `did-witness.json`. */
export type WebVhWitnessProofFileEntry = WitnessProofFileEntry
/** The contents of `did-witness.json`. */
export type WebVhWitnessProofFile = WitnessProofFileEntry[]

export type WebVhUpdateKeyKmsKeyIds = Record<string, Kms.KmsKeyReference>

export enum WebVhDidRecordMetadataKeys {
  // FIXME: refactor to '_internal/webvhDidLog' in next major release
  DidLog = 'log',
  UpdateKeyKmsKeyIds = '_internal/webvhUpdateKeyKmsKeyIds',
  ControllerMetadata = '_internal/webvhControllerMetadata',
  WitnessProofs = '_internal/webvhWitnessProofs',
  ParallelDidWebDocument = '_internal/webvhParallelDidWebDocument',
}
