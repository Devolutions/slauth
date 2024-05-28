package net.devolutions.slauth;

import com.sun.jna.Pointer;
import java.io.Closeable;

abstract class RustObject implements Closeable {
    Pointer raw;
}
