package net.devolutions.slauth;

import com.sun.jna.Pointer;

import java.io.IOException;

public class SigningKey extends RustObject {
    static {
        System.loadLibrary("slauth");
    }

    public SigningKey(Pointer raw) {
        this.raw = raw;
    }

    public SigningKey(String string) throws InvalidSigningKeyException {
        Pointer p = JNA.INSTANCE.signing_key_from_string(string);
        if (p == null) {
            throw new InvalidSigningKeyException();
        }

        this.raw = p;
    }

    public String toString() {
        return JNA.INSTANCE.signing_key_to_string(raw);
    }

    public String getKeyHandle() {
        return JNA.INSTANCE.signing_key_get_key_handle(raw);
    }

    @Override
    public void close() throws IOException {
        JNA.INSTANCE.signing_key_free(raw);
    }
}
