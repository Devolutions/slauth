package net.devolutions.slauth;

import com.sun.jna.Pointer;

import java.io.IOException;
import java.util.Optional;

public class WebRequest extends RustObject {
    static {
        System.loadLibrary("slauth");
    }

    public WebRequest(String json) {
        this.raw = JNA.INSTANCE.web_request_from_json(json);
    }

    public Boolean isRegister() {
        return JNA.INSTANCE.web_request_is_register(raw);
    }

    public Boolean isSign() {
        return JNA.INSTANCE.web_request_is_sign(raw);
    }

    public String getOrigin() {
        return JNA.INSTANCE.web_request_origin(raw);
    }

    public long getTimeout() {
        return JNA.INSTANCE.web_request_timeout(raw);
    }

    public String getKeyHandle(String origin) throws InvalidRequestTypeException {
        if (this.isSign()) {
            return JNA.INSTANCE.web_request_key_handle(raw, origin);
        } else {
            throw new InvalidRequestTypeException();
        }
    }

    public WebResponse register(String origin, byte[] attestationCert, byte[] attestationKey) {
        Pointer p = JNA.INSTANCE.web_request_register(raw, origin, attestationCert, attestationCert.length, attestationKey, attestationKey.length);

        return new WebResponse(p);
    }

    public WebResponse sign(String origin, SigningKey key, int counter, Boolean userPresence) {
        Pointer p = JNA.INSTANCE.web_request_sign(raw, key.raw, origin, counter, userPresence);

        return new WebResponse(p);
    }

    @Override
    public void close() throws IOException {
        JNA.INSTANCE.web_request_free(raw);
    }
}

