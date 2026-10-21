import { KeyManagementError } from './KeyManagementError'

export class KeyManagementKeyMismatchError extends KeyManagementError {
  public constructor(keyId: string) {
    super(`Key with key id '${keyId}' does not match the supplied public JWK`)
  }
}
