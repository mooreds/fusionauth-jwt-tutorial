# Chapter 3: PEM (Privacy-Enhanced Mail) Handling

In the [previous chapter](02_algorithm_enum_.md), we learned about choosing a security `Algorithm` for our JWT. Many powerful algorithms, like `RS256` (RSA) or `ES256` (ECDSA), don't use simple passwords. Instead, they use a pair of **cryptographic keys**: a **private key** (kept secret) and a **public key** (shared openly).

Think of these keys like physical keys to a special lockbox. The private key is used to *lock* (sign) the box (JWT), and the public key can only be used to *check if the lock is valid* (verify the signature).

But how do we store these "digital keys" and get them into our Java application? A very common way is using the **PEM format**.

## What's the Envelope for Our Digital Keys?

Imagine you need to mail a physical key securely. You'd put it in a standard envelope, perhaps with some official markings. PEM (Privacy-Enhanced Mail) is like that standard **envelope format** for cryptographic keys and certificates.

It's a **text-based format**, which makes it super easy to copy, paste, email, or store in configuration files. You can usually recognize a PEM file because it starts and ends with distinctive tags, like:

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD......
...... more lines of seemingly random characters ......
h8RIgerWnOKKCw8=
-----END PRIVATE KEY-----
```

Or maybe:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA......
...... more lines ......
IDAQAB
-----END PUBLIC KEY-----
```

The text between the `-----BEGIN...` and `-----END...` tags is the actual key data, encoded using Base64 (a way to represent binary data using only printable characters).

Our `fusionauth-jwt` library needs to work with these PEM "envelopes". We need tools to:

1.  **Open the envelope (`PEMDecoder`):** Read a PEM string (from a file or variable) and extract the actual Java `PrivateKey` or `PublicKey` object inside.
2.  **Put a key into an envelope (`PEMEncoder`):** Take a Java `PrivateKey` or `PublicKey` object and format it into a standard PEM string.

These tools bridge the gap between the text files where keys are often stored and the Java objects needed by cryptographic functions like signing ([Signer Interface](05_signer_interface_.md)) or verifying ([Verifier Interface](07_verifier_interface_.md)).

## Using `PEMDecoder`: Opening the Envelope

Let's say you have a file named `my_private_key.pem` containing your RSA private key:

```pem
# File: my_private_key.pem
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALKTc7pC8E40
... (many lines of base64 text) ...
P47t9f7fN6z=
-----END PRIVATE KEY-----
```

And another file `my_public_key.pem` for the corresponding public key:

```pem
# File: my_public_key.pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyk3O6QvBONNI7/815yuB7
... (fewer lines of base64 text) ...
AQAB
-----END PUBLIC KEY-----
```

How do we load these into our Java application? We use `PEMDecoder`.

```java
import io.fusionauth.pem.PEMDecoder;
import io.fusionauth.pem.domain.PEM;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

try {
    // Read the content of the private key file into a string
    String privateKeyPEMString = new String(Files.readAllBytes(Paths.get("my_private_key.pem")));

    // Use PEMDecoder to parse the string
    PEMDecoder decoder = new PEMDecoder();
    PEM privatePemObject = decoder.decode(privateKeyPEMString);

    // Extract the Java PrivateKey object
    PrivateKey privateKey = privatePemObject.getPrivateKey();

    System.out.println("Successfully decoded Private Key!");
    // You can now use this 'privateKey' object with a Signer

    // --- Now let's decode the public key ---

    // Read the public key file (alternative: directly use Path with decoder)
    PEM publicPemObject = decoder.decode(Paths.get("my_public_key.pem"));

    // Extract the Java PublicKey object
    PublicKey publicKey = publicPemObject.getPublicKey();

    System.out.println("Successfully decoded Public Key!");
    // You can now use this 'publicKey' object with a Verifier

} catch (Exception e) {
    System.err.println("Error decoding PEM: " + e.getMessage());
    // Handle errors appropriately in real applications
}
```

**Explanation:**

1.  We import the necessary classes (`PEMDecoder`, `PEM`, `Files`, `Paths`, `PrivateKey`, `PublicKey`).
2.  We read the *content* of the `.pem` file into a `String` (or directly use a `Path` object).
3.  We create an instance of `PEMDecoder`.
4.  We call the `decode()` method, passing in either the PEM string or the `Path` to the file.
5.  The `decode()` method returns a `PEM` object. This is a simple container object provided by the library.
6.  We use methods like `getPrivateKey()` or `getPublicKey()` on the `PEM` object to get the standard Java cryptographic key object (`java.security.PrivateKey` or `java.security.PublicKey`).
7.  These `PrivateKey` and `PublicKey` objects are what you'll need for signing and verifying JWTs later.

The `PEMDecoder` intelligently figures out what kind of key or certificate is inside the PEM string based on the `-----BEGIN...` tag (e.g., `PRIVATE KEY`, `PUBLIC KEY`, `CERTIFICATE`, `RSA PRIVATE KEY`).

## Using `PEMEncoder`: Creating the Envelope

Less commonly, you might have a Java `PrivateKey` or `PublicKey` object (perhaps generated in your code) and need to save it to a PEM-formatted string or file. `PEMEncoder` handles this.

```java
import io.fusionauth.pem.PEMEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

try {
    // 1. Generate a key pair (e.g., RSA) - just for this example
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048); // Key size
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    // 2. Create a PEMEncoder instance
    PEMEncoder encoder = new PEMEncoder();

    // 3. Encode the PrivateKey into PEM format
    String privateKeyPEMString = encoder.encode(privateKey);
    System.out.println("--- Encoded Private Key ---");
    System.out.println(privateKeyPEMString);
    // You could now save this string to a .pem file

    // 4. Encode the PublicKey into PEM format
    String publicKeyPEMString = encoder.encode(publicKey);
    System.out.println("\n--- Encoded Public Key ---");
    System.out.println(publicKeyPEMString);
    // You could save this too

} catch (Exception e) {
    System.err.println("Error encoding PEM: " + e.getMessage());
}
```

**Explanation:**

1.  We first get hold of `PrivateKey` and `PublicKey` objects (here, we generate them using Java's standard `KeyPairGenerator`).
2.  We create an instance of `PEMEncoder`.
3.  We call the `encode()` method, passing in the Java key object (`PrivateKey` or `PublicKey`).
4.  The method returns a `String` containing the key formatted correctly with `-----BEGIN...` / `-----END...` tags and the Base64 encoded data.

**Example Output:**

```
--- Encoded Private Key ---
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
... (many lines) ...
-----END PRIVATE KEY-----

--- Encoded Public Key ---
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
... (fewer lines) ...
AQAB
-----END PUBLIC KEY-----
```

## Under the Hood: How Decoding and Encoding Work

Let's peek behind the curtain to see the main steps involved.

### `PEMDecoder` (Reading PEM)

When you call `decoder.decode(pemString)`:

1.  **Find Tags:** The decoder looks for the `-----BEGIN ...-----` and `-----END ...-----` lines to identify the type of data (private key, public key, certificate) and isolate the content.
2.  **Extract Base64:** It grabs the text between the tags and removes any line breaks or whitespace.
3.  **Decode Base64:** It uses Java's standard Base64 decoder to convert this text back into the original raw binary bytes. This binary data is usually in a standard format called **DER (Distinguished Encoding Rules)**, which is a compact binary encoding for structured data.
4.  **Parse DER:** The decoder analyzes the first few bytes of the DER data to understand the key's structure and algorithm (e.g., is it RSA? EC? Is it in PKCS#8 format? X.509 format?).
5.  **Create Java Object:** Based on the analysis, it uses Java's built-in security classes (`java.security.KeyFactory` or `java.security.cert.CertificateFactory`) along with the right "specification" object (like `PKCS8EncodedKeySpec` for standard private keys or `X509EncodedKeySpec` for standard public keys) to convert the DER bytes into a usable Java `PrivateKey`, `PublicKey`, or `Certificate` object.
6.  **Return PEM:** Finally, it wraps the created Java key/certificate object inside the library's `PEM` container object and returns it.

```mermaid
sequenceDiagram
    participant App as Your Application
    participant PEMDecoder as PEMDecoder Instance
    participant PEMString as PEM File Content (String)
    participant Base64Decoder as Java Base64 Decoder
    participant KeyFactory as Java KeyFactory/CertFactory

    App->>PEMDecoder: decode(pemString)
    PEMDecoder->>PEMString: Find BEGIN/END tags
    PEMDecoder->>PEMString: Extract Base64 content
    PEMDecoder->>Base64Decoder: Decode Base64 to bytes (DER)
    Base64Decoder-->>PEMDecoder: Return raw DER bytes
    PEMDecoder->>KeyFactory: generatePrivate/Public(keySpec_from_bytes)
    KeyFactory-->>PEMDecoder: Return PrivateKey/PublicKey Object
    PEMDecoder-->>App: Return PEM object (containing key)
```

Looking at the code (`PEMDecoder.java`), you can see pieces of this logic:

```java
// Simplified from: main/java/io/fusionauth/pem/PEMDecoder.java
public class PEMDecoder {

    // ... (decode method that figures out the type based on tags) ...

    // Helper to get the raw bytes from between the tags
    private byte[] getKeyBytes(String key, String keyPrefix, String keySuffix) {
        int startIndex = key.indexOf(keyPrefix);
        int endIndex = key.indexOf(keySuffix);

        // Extract text between tags, remove whitespace
        String base64 = key.substring(startIndex + keyPrefix.length(), endIndex)
                         .replaceAll("\\s+", "");
        // Decode Base64
        return Base64.getDecoder().decode(base64);
    }

    // Example for decoding a standard PKCS#8 Private Key
    private PEM decode_PKCS_8(String encodedKey) throws Exception {
        // 1 & 2: Get bytes (calls getKeyBytes)
        byte[] bytes = getKeyBytes(encodedKey, PKCS_8_PRIVATE_KEY_PREFIX, PKCS_8_PRIVATE_KEY_SUFFIX);

        // 3, 4 & 5: Use Java KeyFactory to parse DER bytes
        // (Determine algorithm type - RSA, EC, etc. - from DER bytes first - simplified here)
        String algorithm = determineAlgorithmFromBytes(bytes); // Helper not shown
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm); // e.g., "RSA" or "EC"
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // (Try to extract public key if included - simplified here)
        PublicKey publicKey = tryExtractPublicKey(privateKey);

        // 6. Return PEM object
        return new PEM(privateKey, publicKey);
    }

     // Example for decoding a standard X.509 Public Key
    private PEM decode_X_509(String encodedKey) throws Exception {
        byte[] bytes = getKeyBytes(encodedKey, X509_PUBLIC_KEY_PREFIX, X509_PUBLIC_KEY_SUFFIX);

        String algorithm = determineAlgorithmFromBytes(bytes); // Helper not shown
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm); // e.g., "RSA" or "EC"
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return new PEM(publicKey);
    }
    // ... other decode methods for PKCS#1, EC private keys, Certificates ...
}
```

### `PEMEncoder` (Writing PEM)

When you call `encoder.encode(privateKey)`:

1.  **Get Encoded Bytes:** It calls the `.getEncoded()` method on the provided Java `PrivateKey` or `PublicKey` object. This method returns the key's standard DER-encoded byte representation (e.g., PKCS#8 for `PrivateKey`, X.509 for `PublicKey`).
2.  **Encode Base64:** It encodes these raw DER bytes into a Base64 string. It typically uses the "MIME" variant of Base64, which inserts line breaks every 64 characters, making it look like the standard PEM format.
3.  **Add Tags:** It determines the correct `-----BEGIN...` and `-----END...` tags based on the type of key (`PrivateKey`, `PublicKey`) and its format (`key.getFormat()`, e.g., "PKCS#8", "X.509").
4.  **Combine and Return:** It constructs the final string by putting the opening tag, the Base64 encoded content (with line breaks), and the closing tag together.

```java
// Simplified from: main/java/io/fusionauth/pem/PEMEncoder.java
public class PEMEncoder {
    // MIME Base64 encoder with line breaks every 64 chars
    private static final Base64.Encoder Base64_MIME_Encoder = Base64.getMimeEncoder(64, new byte[]{'\n'});

    public String encode(Key key) {
        if (key instanceof PrivateKey) {
            return encodePrivateKey((PrivateKey) key);
        } else if (key instanceof PublicKey) {
            return encodePublicKey((PublicKey) key);
        }
        // ... error handling ...
        return null;
    }

    private String encodePrivateKey(PrivateKey privateKey) {
        StringBuilder sb = new StringBuilder();
        // 3. Add opening tag (checks format like PKCS#8)
        addOpeningTag(privateKey, sb);

        // 1. Get DER bytes
        byte[] derBytes = privateKey.getEncoded();
        // 2. Encode to Base64 with line breaks
        String base64Encoded = Base64_MIME_Encoder.encodeToString(derBytes);
        sb.append(base64Encoded);

        // 3. Add closing tag
        addClosingTag(privateKey, sb);
        // 4. Return final string
        return sb.toString();
    }

    // ... similar method for PublicKey ...
    // ... helper methods addOpeningTag / addClosingTag ...
}
```

## Conclusion

You've now learned how to handle the common PEM format for cryptographic keys and certificates using the `fusionauth-jwt` library!

*   You understand that PEM is a **text-based "envelope"** for keys/certs, marked by `-----BEGIN...` and `-----END...` tags.
*   You know that `PEMDecoder` **reads** these PEM strings/files and converts them into standard Java `PrivateKey`, `PublicKey`, or `Certificate` objects.
*   You know that `PEMEncoder` **writes** Java key/certificate objects back into the PEM string format.
*   You have a basic idea of the internal steps involving Base64 decoding/encoding and using Java's `KeyFactory`.

These decoded keys are essential for the next steps in the JWT process: actually signing the token ([Signer Interface](05_signer_interface_.md)) or verifying a token you received ([Verifier Interface](07_verifier_interface_.md)).

While PEM is very common, especially for files, there's another popular format for representing keys, particularly in web APIs, called JSON Web Key (JWK). Let's explore that next!

Next: [Chapter 4: JSONWebKey (JWK) Handling](04_jsonwebkey__jwk__handling_.md)

---

Generated by [AI Codebase Knowledge Builder](https://github.com/The-Pocket/Tutorial-Codebase-Knowledge)