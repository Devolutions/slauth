package net.devolutions.slauth;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

public interface JNA extends Library {
    String JNA_LIBRARY_NAME = "slauth";

    JNA INSTANCE = Native.load(JNA_LIBRARY_NAME, JNA.class);

    Pointer hotp_from_uri(String uri);

    void hotp_free(Pointer hotp);

    String hotp_gen(Pointer hotp);

    void hotp_inc(Pointer hotp);

    String hotp_to_uri(Pointer hotp, String label, String issuer);

    Boolean hotp_validate_current(Pointer hotp, String code);

    Boolean hotp_verify(Pointer hotp, String code);

    void totp_free(Pointer totp);

    Pointer totp_from_uri(String uri);

    String totp_gen(Pointer totp);

    String totp_gen_with(Pointer totp, long elapsed);

    String totp_to_uri(Pointer totp, String label, String issuer);

    Boolean totp_validate_current(Pointer totp, String code);

    Boolean totp_verify(Pointer totp, String code);

    void client_web_response_free(Pointer rsp);

    Pointer client_web_response_signing_key(Pointer rsp);

    String client_web_response_to_json(Pointer rsp);

    void signing_key_free(Pointer s);

    Pointer signing_key_from_string(String s);

    String signing_key_to_string(Pointer s);

    String signing_key_get_key_handle(Pointer s);

    void web_request_free(Pointer req);

    Pointer web_request_from_json(String req);

    Boolean web_request_is_register(Pointer req);

    Boolean web_request_is_sign(Pointer req);

    String web_request_key_handle(Pointer req, String origin);

    String web_request_origin(Pointer req);

    Pointer web_request_register(Pointer req, String origin, byte[] attestation_cert, long attestation_cert_len, byte[] attestation_key, long attestation_key_len);

    Pointer web_request_sign(Pointer req, Pointer signing_key, String origin, long counter, Boolean user_presence);

    long web_request_timeout(Pointer req);
}
