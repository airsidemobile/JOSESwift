import Foundation

struct JWSSigningInput {

    let header: JWSHeader

    let payload: Payload

    func signingInput() throws -> Data {
        let headerData = try computeHeaderData()
        let payloadData = try computePayloadData()

        // Force unwrapping is ok, since `".".data(using: .ascii)` should always work.
        // swiftlint:disable:next force_unwrapping
        return headerData + ".".data(using: .ascii)! + payloadData
    }

    private func computeHeaderData() throws -> Data {
        guard let headerData = header.data().base64URLEncodedString().data(using: .ascii) else {
            throw JWSError.cannotComputeSigningInput
        }
        return headerData
    }

    private func computePayloadData() throws -> Data {
        let encodePayload = (header.crit?.contains("b64") == true)
            ? (header.b64 ?? true)
            : true

        if encodePayload {
            guard let encodedPayload = payload.data().base64URLEncodedString().data(using: .ascii) else {
                throw JWSError.cannotComputeSigningInput
            }
            return encodedPayload
        } else if let typ = header.typ, typ.caseInsensitiveCompare("jwt") == .orderedSame {
            throw JWSError.unencodedPayloadOptionMustNotBeUsedWithJWT
        } else {
            return payload.data()
        }
    }

}
