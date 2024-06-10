package net.devolutions.slauth;

public enum AttestationFlags {
    USER_PRESENT(1),
    //Reserved for future (2)
    USER_VERIFIED(4),
    BACKUP_ELIGIBLE(8),
    BACKED_UP(16),
    //Reserved for future (32)
    ATTESTED_CREDENTIAL_DATA_INCLUDED(64),
    EXTENSION_DATA_INCLUDED(128);

    private final int value;

    AttestationFlags(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}