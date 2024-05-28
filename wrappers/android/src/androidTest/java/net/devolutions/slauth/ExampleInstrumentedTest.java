package net.devolutions.slauth;

import android.support.test.runner.AndroidJUnit4;
import android.util.Base64;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void totpUris() {
        String baseUri = "otpauth://totp/john.doe@email.com?secret=12a9f88729b3bf4477f76b6c65d0e144d8ddc8f1&algorithm=SHA1&digits=6&period=30&issuer=Slauth";
        Totp totp = null;
        try {
            totp = new Totp(baseUri);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String genUri = totp.toUri("john.doe@email.com", "Slauth");

        System.out.println(genUri);

        //assertEquals(baseUri, genUri); No more equal since the baseuri use hex

        String code1 = totp.gen();

        try {
            Thread.sleep(31000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        String code2 = totp.genWith(31);

        assertEquals(code1, code2);
    }

    @Test
    public void u2fTest() {
        try {
            byte[] att_cert = android.util.Base64.decode("MIICODCCAd6gAwIBAgIJAKsa9WC9HvEuMAoGCCqGSM49BAMCMFoxDzANBgNVBAMMBlNsYXV0aDELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzETMBEGA1UEBwwKTGF2YWx0cm91ZTEUMBIGA1UECgwLRGV2b2x1dGlvbnMwHhcNMTkwNzAyMTgwMTUyWhcNMzEwNjI5MTgwMTUyWjBaMQ8wDQYDVQQDDAZTbGF1dGgxCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWViZWMxEzARBgNVBAcMCkxhdmFsdHJvdWUxFDASBgNVBAoMC0Rldm9sdXRpb25zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE15PAnpUUIzbgKxD6RFuNMjjl/cD06vKRBtl0X/CiNzc3igTh1qcc00QICgAQUxdvHSn+DaSRki/kI9OJ8lkPGqOBjDCBiTAdBgNVHQ4EFgQU7iZ4JceUHOuWoMymFGm+ZBUmwwgwHwYDVR0jBBgwFoAU7iZ4JceUHOuWoMymFGm+ZBUmwwgwDgYDVR0PAQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAVBgNVHREEDjAMggpzbGF1dGgub3JnMAoGCCqGSM49BAMCA0gAMEUCIEdjPFNsund4FXs/1HpK4AXWQ0asfY6ERhNlg29VGS6pAiEAx8f2lrlVV1tASWbC/edTgH9JsCbANuXW/9FZcWHGl2E=", Base64.DEFAULT);
            byte[] att_key = android.util.Base64.decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzgUSoDttmryF0C+ck4GppKwssha7ngah0dfezfTBzDOhRANCAATXk8CelRQjNuArEPpEW40yOOX9wPTq8pEG2XRf8KI3NzeKBOHWpxzTRAgKABBTF28dKf4NpJGSL+Qj04nyWQ8a", Base64.DEFAULT);

            String json = "{\"appId\":\"https://login.devolutions.com/\",\"registerRequests\":[{\"challenge\":\"UzAxNE0yMTBWM1JDYzA1a1JqWndRUT09\",\"version\":\"U2F_V2\"}],\"registeredKeys\":[],\"requestId\":1,\"timeoutSeconds\":300,\"type\":\"u2f_register_request\"}";

            WebRequest web_r = new WebRequest(json);

            String origin = web_r.getOrigin();

            WebResponse rsp = web_r.register(origin, att_cert, att_key);

            SigningKey key = rsp.getSigningKey();

            System.out.println(key.getKeyHandle());
            System.out.println(key.toString());
            System.out.println(rsp.toJson());
        } catch (InvalidResponseTypeException e) {
            e.printStackTrace();
        }
    }
}
