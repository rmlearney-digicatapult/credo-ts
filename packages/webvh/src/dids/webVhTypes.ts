import type { Kms } from '@credo-ts/core'
import type { DIDLog, DIDLogEntry } from 'didwebvh-ts'

// Keep upstream log types available through the Credo package API.
export type WebVhDidLog = DIDLog
export type WebVhDidLogEntry = DIDLogEntry

export type WebVhUpdateKeyKmsKeyIds = Record<string, Kms.KmsKeyReference>

export enum WebVhDidRecordMetadataKeys {
  // FIXME: refactor to '_internal/webvhDidLog' in next major release
  DidLog = 'log',
  UpdateKeyKmsKeyIds = '_internal/webvhUpdateKeyKmsKeyIds',
  ControllerMetadata = '_internal/webvhControllerMetadata',
  WitnessProofs = '_internal/webvhWitnessProofs',
  ParallelDidWebDocument = '_internal/webvhParallelDidWebDocument',
}
