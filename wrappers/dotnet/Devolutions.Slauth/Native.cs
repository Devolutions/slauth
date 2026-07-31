namespace Devolutions.Slauth;

using System;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// Raw P/Invoke surface over slauth's C ABI (see slauth.h at the repository root).
/// </summary>
/// <remarks>
/// Three ownership rules apply to everything declared here, and the public wrapper types are what
/// enforce them:
/// <list type="bullet">
/// <item>Response pointers must be released with their matching free function — hence the SafeHandles.</item>
/// <item><c>char*</c> returns are Rust <c>CString::into_raw</c> allocations. They must go back through
/// <c>slauth_string_free</c>; the caller's <c>free</c> is a different allocator.</item>
/// <item>A returned <see cref="Buffer"/> borrows the response's own storage, so it is only valid until
/// the response is freed. Copy out before releasing the handle.</item>
/// </list>
/// </remarks>
internal static class Native
{
    private const string Library = "slauth";

    [StructLayout(LayoutKind.Sequential)]
    internal struct Buffer
    {
        public IntPtr Data;
        public UIntPtr Len;
    }

    [DllImport(Library, EntryPoint = "generate_credential_creation_response", CallingConvention = CallingConvention.Cdecl)]
    internal static extern CreationResponseHandle GenerateCredentialCreationResponse(
        IntPtr aaguid,
        byte[] credentialId,
        UIntPtr credentialIdLength,
        IntPtr rpId,
        byte attestationFlags,
        int[] coseAlgorithmIdentifiers,
        UIntPtr coseAlgorithmIdentifiersLength);

    [DllImport(Library, EntryPoint = "get_private_key_from_response", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr GetPrivateKeyFromResponse(CreationResponseHandle response);

    [DllImport(Library, EntryPoint = "get_attestation_object_from_response", CallingConvention = CallingConvention.Cdecl)]
    internal static extern Buffer GetAttestationObjectFromResponse(CreationResponseHandle response);

    [DllImport(Library, EntryPoint = "response_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void ResponseFree(IntPtr response);

    [DllImport(Library, EntryPoint = "generate_credential_request_response", CallingConvention = CallingConvention.Cdecl)]
    internal static extern RequestResponseHandle GenerateCredentialRequestResponse(
        IntPtr rpId,
        IntPtr privateKey,
        byte attestationFlags,
        byte[] clientDataHash,
        UIntPtr clientDataHashLength);

    [DllImport(Library, EntryPoint = "get_auth_data_from_response", CallingConvention = CallingConvention.Cdecl)]
    internal static extern Buffer GetAuthDataFromResponse(RequestResponseHandle response);

    [DllImport(Library, EntryPoint = "get_signature_from_response", CallingConvention = CallingConvention.Cdecl)]
    internal static extern Buffer GetSignatureFromResponse(RequestResponseHandle response);

    [DllImport(Library, EntryPoint = "is_success", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool IsSuccess(RequestResponseHandle response);

    [DllImport(Library, EntryPoint = "get_error_message", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr GetErrorMessage(RequestResponseHandle response);

    [DllImport(Library, EntryPoint = "request_response_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void RequestResponseFree(IntPtr response);

    [DllImport(Library, EntryPoint = "private_key_to_pkcs8_der", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr PrivateKeyToPkcs8Der(IntPtr privateKey);

    [DllImport(Library, EntryPoint = "pkcs8_to_custom_private_key", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr Pkcs8ToCustomPrivateKey(IntPtr pkcs8Key);

    [DllImport(Library, EntryPoint = "slauth_string_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void SlauthStringFree(IntPtr value);

    /// <summary>Copies a borrowed buffer out before its owning response is released.</summary>
    internal static byte[] CopyBuffer(Buffer buffer)
    {
        if (buffer.Data == IntPtr.Zero || (ulong)buffer.Len == 0)
        {
            return Array.Empty<byte>();
        }

        byte[] copy = new byte[(int)(ulong)buffer.Len];
        Marshal.Copy(buffer.Data, copy, 0, copy.Length);
        return copy;
    }
}

/// <summary>
/// UTF-8 marshalling done by hand: slauth reads Rust <c>CStr</c>, so the platform's default ANSI
/// marshalling would corrupt any non-ASCII value (a relying party id can be an IDN).
/// </summary>
internal static class Utf8
{
    /// <summary>Allocates a NUL-terminated UTF-8 copy. Release with <see cref="Free"/>.</summary>
    internal static IntPtr Allocate(string? value)
    {
        if (value is null)
        {
            return IntPtr.Zero;
        }

        byte[] bytes = Encoding.UTF8.GetBytes(value);
        IntPtr pointer = Marshal.AllocHGlobal(bytes.Length + 1);
        Marshal.Copy(bytes, 0, pointer, bytes.Length);
        Marshal.WriteByte(pointer, bytes.Length, 0);
        return pointer;
    }

    internal static void Free(IntPtr pointer)
    {
        if (pointer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    /// <summary>
    /// Reads a NUL-terminated UTF-8 string that slauth allocated, then hands the allocation back to
    /// slauth. Never use the caller's <c>free</c> here — the string came from Rust.
    /// </summary>
    internal static string? ConsumeSlauthString(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            int length = 0;
            while (Marshal.ReadByte(pointer, length) != 0)
            {
                length++;
            }

            byte[] bytes = new byte[length];
            Marshal.Copy(pointer, bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            Native.SlauthStringFree(pointer);
        }
    }
}

/// <summary>Owns an <c>AuthenticatorCreationResponse*</c>.</summary>
internal sealed class CreationResponseHandle : SafeHandle
{
    public CreationResponseHandle()
        : base(IntPtr.Zero, true)
    {
    }

    public override bool IsInvalid => this.handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.ResponseFree(this.handle);
        return true;
    }
}

/// <summary>Owns an <c>AuthenticatorRequestResponse*</c>.</summary>
internal sealed class RequestResponseHandle : SafeHandle
{
    public RequestResponseHandle()
        : base(IntPtr.Zero, true)
    {
    }

    public override bool IsInvalid => this.handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.RequestResponseFree(this.handle);
        return true;
    }
}
