import { DidCommRevocationNotificationProcessorToken } from '@credo-ts/didcomm'
import { getAgentContext } from '../../../../core/tests/helpers'
import { NativeAnoncreds } from '../../../tests/helpers'
import { AnonCredsModuleConfig } from '../../AnonCredsModuleConfig'
import { AnonCredsDidCommModule } from '../../didcomm/AnonCredsDidCommModule'
import type { AnonCredsProofRequest } from '../../models'
import type { AnonCredsRegistry } from '../../services'
import { areAnonCredsProofRequestsEqual } from '../areRequestsEqual'
import {
  areIdentifiersEqual,
  getIdentifierVariants,
  identifierQuery,
  withCanonicalRestrictionIdentifiers,
  withIdentifierQueryVariants,
  withIdentifierVariantKeys,
  withProofRequestRestrictionVariants,
} from '../identifierVariants'

const registry = {
  supportedIdentifier: /^test:/,
  getIdentifierVariants(identifier: string) {
    const canonical = identifier === 'test:encoded' ? 'test:plain' : identifier
    return [canonical, 'test:encoded']
  },
} as unknown as AnonCredsRegistry

function getContext(withVariantRegistry = true) {
  return getAgentContext({
    registerInstances: [
      [
        AnonCredsModuleConfig,
        new AnonCredsModuleConfig({
          registries: [withVariantRegistry ? registry : ({ supportedIdentifier: /^test:/ } as AnonCredsRegistry)],
          anoncreds: NativeAnoncreds,
        }),
      ],
    ],
  })
}

describe('identifier variants', () => {
  test('uses the registry canonical form and includes the original identifier', () => {
    const agentContext = getContext()

    expect(getIdentifierVariants(agentContext, 'test:plain')).toEqual(['test:plain', 'test:encoded'])
    expect(getIdentifierVariants(agentContext, 'test:encoded')).toEqual(['test:plain', 'test:encoded'])
    expect(areIdentifiersEqual(agentContext, 'test:plain', 'test:encoded')).toBe(true)
    expect(areIdentifiersEqual(agentContext, 'test:plain', 'test:other')).toBe(false)
  })

  test('keeps identity behavior when the registry does not provide variants', () => {
    const agentContext = getContext(false)

    expect(getIdentifierVariants(agentContext, 'test:encoded')).toEqual(['test:encoded'])
    expect(areIdentifiersEqual(agentContext, 'test:plain', 'test:encoded')).toBe(false)
  })

  test('adds identifier aliases to storage queries without dropping other filters', () => {
    const agentContext = getContext()

    expect(
      withIdentifierQueryVariants(agentContext, { credentialDefinitionId: 'test:encoded', state: 'active' }, [
        'credentialDefinitionId',
      ])
    ).toEqual({
      $and: [
        { state: 'active' },
        { $or: [{ credentialDefinitionId: 'test:plain' }, { credentialDefinitionId: 'test:encoded' }] },
      ],
    })
    expect(identifierQuery(agentContext, 'schemaId', 'test:encoded')).toEqual({
      $or: [{ schemaId: 'test:plain' }, { schemaId: 'test:encoded' }],
    })
  })

  test('expands restriction forms and canonicalizes comparisons', () => {
    const agentContext = getContext()
    const encodedRequest = {
      name: 'proof',
      version: '1.0',
      nonce: '1',
      requested_attributes: { name: { name: 'name', restrictions: [{ schema_id: 'test:encoded' }] } },
      requested_predicates: {},
    } satisfies AnonCredsProofRequest
    const plainRequest = {
      ...encodedRequest,
      requested_attributes: { name: { name: 'name', restrictions: [{ schema_id: 'test:plain' }] } },
    } satisfies AnonCredsProofRequest

    expect(
      withProofRequestRestrictionVariants(agentContext, encodedRequest).requested_attributes.name.restrictions
    ).toEqual([{ schema_id: 'test:plain' }, { schema_id: 'test:encoded' }])
    expect(withCanonicalRestrictionIdentifiers(agentContext, encodedRequest)).toEqual(plainRequest)
    expect(
      areAnonCredsProofRequestsEqual(
        withCanonicalRestrictionIdentifiers(agentContext, encodedRequest),
        withCanonicalRestrictionIdentifiers(agentContext, plainRequest)
      )
    ).toBe(true)
  })

  test('preserves explicit native object-map keys over generated aliases', () => {
    const agentContext = getContext()
    const canonical = { value: 'canonical' }
    const explicitEncoded = { value: 'explicit' }

    expect(
      withIdentifierVariantKeys(agentContext, {
        'test:plain': canonical,
        'test:encoded': explicitEncoded,
      })
    ).toEqual({
      'test:plain': canonical,
      'test:encoded': explicitEncoded,
    })
  })

  test('registers a notification processor through the DIDComm integration module', () => {
    const agentContext = getContext()
    new AnonCredsDidCommModule().register(agentContext.dependencyManager)

    expect(agentContext.dependencyManager.isRegistered(DidCommRevocationNotificationProcessorToken, true)).toBe(true)
  })
})
