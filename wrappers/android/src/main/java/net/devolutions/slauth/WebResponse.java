package net.devolutions.slauth;

import com.sun.jna.Pointer;

import java.io.IOException;

public class WebResponse extends RustObject {
    static {
        System.loadLibrary("slauth");
    }

    public WebResponse(Pointer raw) {
        this.raw = raw;
    }

    public String toJson() {
        return JNA.INSTANCE.client_web_response_to_json(raw);
    }

    public SigningKey getSigningKey() throws InvalidResponseTypeException {
        Pointer p = JNA.INSTANCE.client_web_response_signing_key(raw);

        if (p == null) {
            throw new InvalidResponseTypeException();
        }

        return new SigningKey(p);
    }


    @Override
    public void close() throws IOException {
        JNA.INSTANCE.client_web_response_free(raw);
    }
}

