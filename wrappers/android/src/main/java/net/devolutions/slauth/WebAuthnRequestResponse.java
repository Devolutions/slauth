package net.devolutions.slauth;

import java.io.IOException;

public class WebAuthnRequestResponse extends RustObject {
    static {
        System.loadLibrary("slauth");
    }

    public WebAuthnRequestResponse(byte[] credentialId, String requestJson, String origin, byte attestationFlags, byte[] userHandle, String privateKey) throws Exception {
        this.raw = JNA.INSTANCE.generate_credential_request_response(credentialId, credentialId.length, requestJson, origin, attestationFlags, userHandle, userHandle.length, privateKey);
        if (this.raw == null) {
            throw new Exception();
        }

        String json = this.getJson();
        if (json == null || json.isEmpty()) {
            throw new Exception(this.getError());
        }
    }

    public String getJson() {
        return JNA.INSTANCE.get_json_from_request_response(raw);
    }

    public String getError() {
        return JNA.INSTANCE.get_error_from_request_response(raw);
    }

    @Override
    public void close() throws IOException {
        JNA.INSTANCE.response_free(raw);
    }
}
