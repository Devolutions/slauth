package net.devolutions.slauth;

public class SlauthUtils {
    static {
        System.loadLibrary("slauth_jni");
    }

    public String privateKeyToPkcs8Der(String key) {
        return JNA.INSTANCE.private_key_to_pkcs8_der(key);
    }

    public String Pkcs8ToCustomPrivateKey(String key) {
        return JNA.INSTANCE.pkcs8_to_custom_private_key(key);
    }
}