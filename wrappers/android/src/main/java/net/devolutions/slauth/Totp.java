package net.devolutions.slauth;

import java.io.IOException;

public class Totp extends RustObject {
    static {
        System.loadLibrary("slauth");
    }

    public Totp(String uri) throws Exception {
        this.raw = JNA.INSTANCE.totp_from_uri(uri);
        if (this.raw == null) {
            throw new Exception();
        }
    }

    public String gen() {
        return JNA.INSTANCE.totp_gen(raw);
    }

    public String genWith(long elapsed) {
        return JNA.INSTANCE.totp_gen_with(raw, elapsed);
    }

    public String toUri(String label, String issuer) {
        return JNA.INSTANCE.totp_to_uri(raw, label, issuer);
    }

    public Boolean validateCurrent(String code) {
        return JNA.INSTANCE.totp_validate_current(raw, code);
    }

    public Boolean verify(String code) {
        return JNA.INSTANCE.totp_verify(raw, code);
    }

    @Override
    public void close() throws IOException {
        JNA.INSTANCE.totp_free(raw);
    }
}
