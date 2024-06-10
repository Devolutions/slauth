package net.devolutions.slauth;

import java.io.IOException;

public class WebAuthnCreationResponse extends RustObject {
    static {
        System.loadLibrary("slauth");
    }

    public WebAuthnCreationResponse(String aaguid, byte[] credentialId, String requestJson, String origin, byte attestationFlags) throws Exception {
        this.raw = JNA.INSTANCE.generate_credential_creation_response(aaguid, credentialId, credentialId.length, requestJson, origin, attestationFlags);
        if (this.raw == null) {
            throw new Exception();
        }

        String json = this.getJson();
        if (json == null || json.isEmpty()) {
            throw new Exception(this.getError());
        }
    }

    public String getJson() {
        return JNA.INSTANCE.get_json_from_creation_response(raw);
    }

    public String getPrivateKey() {
        return JNA.INSTANCE.get_private_key_from_response(raw);
    }

    public String getError() {
        return JNA.INSTANCE.get_error_from_creation_response(raw);
    }

    @Override
    public void close() throws IOException {
        JNA.INSTANCE.response_free(raw);
    }
}

