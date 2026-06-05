import type { ValidationOptions } from 'class-validator'

import { buildMessage, isString, isURL, ValidateBy } from 'class-validator'
import { CredoError } from '../../error'
import { isJsonObject } from '../../types'
import {
  CREDENTIALS_CONTEXT_V1_URL,
  CREDENTIALS_CONTEXT_V2_URL,
  VERIFIABLE_CREDENTIAL_TYPE,
  VERIFIABLE_PRESENTATION_TYPE,
} from './constants'

export interface IsCredentialJsonLdContextValidationOptions extends ValidationOptions {
  /**
   * Whether to allow string value in addition to arrays.
   *
   * @default false
   */
  allowString?: boolean

  /**
   * The expected credential context URL.
   *
   * @default {@link CREDENTIALS_CONTEXT_V1_URL}
   */
  credentialContext?: string
}

export function IsCredentialJsonLdContext(
  validationOptions?: IsCredentialJsonLdContextValidationOptions
): PropertyDecorator {
  const allowString = validationOptions?.allowString ?? false
  const credentialContext = validationOptions?.credentialContext ?? CREDENTIALS_CONTEXT_V1_URL

  return ValidateBy(
    {
      name: 'IsCredentialJsonLdContext',
      validator: {
        validate: (value): boolean => {
          if (!Array.isArray(value)) return allowString && isString(value) && value === credentialContext

          // First item must be the verifiable credential context
          if (value[0] !== credentialContext) return false

          return value.every((v) => (isString(v) && isURL(v)) || isJsonObject(v))
        },
        defaultMessage: buildMessage(
          (eachPrefix) =>
            `${eachPrefix}$property must be an array of strings or objects, where the first item is the verifiable credential context URL.`,
          validationOptions
        ),
      },
    },
    validationOptions
  )
}

export function IsCredentialType(validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'IsVerifiableCredentialType',
      validator: {
        validate: (value): boolean => {
          return Array.isArray(value)
            ? value.includes(VERIFIABLE_CREDENTIAL_TYPE) && value.every((v) => typeof v === 'string')
            : value === VERIFIABLE_CREDENTIAL_TYPE
        },
        defaultMessage: buildMessage(
          (eachPrefix) =>
            `${eachPrefix}$property must be "VerifiableCredential" or an array of strings which includes "VerifiableCredential"`,
          validationOptions
        ),
      },
    },
    validationOptions
  )
}

export function IsVerifiablePresentationType(validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'IsVerifiablePresentationType',
      validator: {
        validate: (value): boolean => {
          return Array.isArray(value)
            ? value.includes(VERIFIABLE_PRESENTATION_TYPE) && value.every((v) => typeof v === 'string')
            : value === VERIFIABLE_PRESENTATION_TYPE
        },
        defaultMessage: buildMessage(
          (eachPrefix) =>
            `${eachPrefix}$property must be "VerifiablePresentation" or an array of strings which includes "VerifiablePresentation"`,
          validationOptions
        ),
      },
    },
    validationOptions
  )
}

export interface ValidationResult {
  isValid: boolean
  error?: Error
}

export interface ValidateVc2CredentialValidityPeriodOptions {
  validFrom?: string
  validUntil?: string
  skewSeconds: number
  now?: number
}

export interface ValidateVc2ContextBaselineOptions {
  /**
   * Overrides the baseline VC2 first-context requirement for specialized validation profiles.
   *
   * By default, baseline validation enforces VC Data Model 2.x semantics where the first
   * top-level `@context` entry is `CREDENTIALS_CONTEXT_V2_URL`.
   *
   * This override exists so stricter or alternate profile validators can reuse baseline
   * structural checks (ordered-set shape, non-empty, URL/object entries) without forcing
   * that specific first-entry rule. One example is Data Integrity profile validation, which
   * applies its own `knownContext` equality policy after baseline checks.
   *
   * Use this only in profile-specific validation layers; issuer/verifier VC2 baseline paths
   * should rely on the default and remain spec-conformant.
   */
  requiredFirstContext?: string | null
}

export function validateVc2ContextBaseline(
  context: unknown,
  options: ValidateVc2ContextBaselineOptions = {}
): ValidationResult {
  const requiredFirstContext =
    options.requiredFirstContext === undefined ? CREDENTIALS_CONTEXT_V2_URL : options.requiredFirstContext

  const contextArray = Array.isArray(context)
    ? context
    : typeof context === 'string'
      ? [context]
      : undefined

  if (!contextArray) {
    return {
      isValid: false,
      error: new CredoError('VC2 @context must be an ordered set'),
    }
  }

  if (contextArray.length === 0) {
    return {
      isValid: false,
      error: new CredoError('VC2 @context must not be empty'),
    }
  }

  if (requiredFirstContext && contextArray[0] !== requiredFirstContext) {
    return {
      isValid: false,
      error: new CredoError(`VC2 @context must start with '${requiredFirstContext}'`),
    }
  }

  const hasOnlyValidEntries = contextArray.every((entry) => {
    if (typeof entry === 'string') return isURL(entry)
    return isJsonObject(entry)
  })

  if (!hasOnlyValidEntries) {
    return {
      isValid: false,
      error: new CredoError('VC2 @context entries must be URLs or JSON objects'),
    }
  }

  return {
    isValid: true,
  }
}

export function validateVc2CredentialStatus(options: {
  credentialStatus?: unknown
  credentialFormat: 'JWT' | 'SD-JWT'
}): ValidationResult {
  if (!options.credentialStatus) {
    return {
      isValid: true,
    }
  }

  return {
    isValid: false,
    error: new CredoError(
      `Verifying credential status is not supported for W3C VC2 ${options.credentialFormat} credentials`
    ),
  }
}

export function validateVc2CredentialValidityPeriod(
  options: ValidateVc2CredentialValidityPeriodOptions
): ValidationResult {
  const now = options.now ?? Math.floor(Date.now() / 1000)

  const validFromTimestamp = options.validFrom ? Math.floor(Date.parse(options.validFrom) / 1000) : undefined
  const validUntilTimestamp = options.validUntil ? Math.floor(Date.parse(options.validUntil) / 1000) : undefined

  if (
    validFromTimestamp !== undefined &&
    validUntilTimestamp !== undefined &&
    validFromTimestamp > validUntilTimestamp
  ) {
    return {
      isValid: false,
      error: new CredoError('Credential validFrom must be temporally equal to or before validUntil'),
    }
  }

  if (validFromTimestamp !== undefined && validFromTimestamp - options.skewSeconds > now) {
    return {
      isValid: false,
      error: new CredoError('Credential is not valid yet based on validFrom'),
    }
  }

  if (validUntilTimestamp !== undefined && validUntilTimestamp + options.skewSeconds < now) {
    return {
      isValid: false,
      error: new CredoError('Credential is no longer valid based on validUntil'),
    }
  }

  return {
    isValid: true,
  }
}
