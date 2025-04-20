# Chapter 8: JWTDecoder

Welcome to the final chapter of our JWT tutorial! In the [previous chapter](07_verifier_interface_.md), we learned about the [Verifier Interface](07_verifier_interface_.md) – the "border control officer" responsible for checking the digital signature on a JWT. We now have the tools to create JWTs ([JWTEncoder](06_jwtencoder_.md)) and the specifications for how to verify their signatures ([Verifier Interface](07_verifier_interface_.md)).

But how do we put it all together when we *receive* a JWT string (like `xxxxx.yyyyy.zzzzz`)? We need a comprehensive process to take that compact string, check its validity thoroughly, and finally extract the useful information (the claims) inside.

**Use Case:** Imagine your web application receives an authentication token (a JWT) from a user who just logged in via a central identity server. Your application needs to:
1.  Read the token string.
2.  Verify that the token is authentic and hasn't been tampered with (check the signature).
3.  Ensure the token hasn't expired.
4.  Extract the user's ID and permissions from the token's claims to grant them access.

This entire process is handled by the `JWTDecoder`.

## The Full Inspection Station: What is the JWTDecoder?

Think of the `JWTDecoder` as the **complete inspection station** at the border crossing. The [Verifier Interface](07_verifier_interface_.md) was just the officer focused on the passport's security seal. The `JWTDecoder` manages the *entire* process:

1.  **Receives the Passport:** Takes the compact JWT string (the laminated passport).
2.  **Opens and Reads:** Splits the string into its three parts (header, payload, signature).
3.  **Checks the Cover:** Decodes the header to see which security method (`alg`) was used and potentially which key (`kid`) was used.
4.  **Finds the Right Officer:** Selects the appropriate [Verifier Interface](07_verifier_interface_.md) capable of checking that specific algorithm (and potentially key).
5.  **Verifies the Seal:** Uses the chosen [Verifier Interface](07_verifier_interface_.md) to check if the signature matches the header and payload data. If not, it rejects the passport immediately.
6.  **Checks Dates:** Verifies standard time-based claims, like checking if the passport has expired (`exp`) or if it's not yet valid (`nbf`). It allows for a small grace period (clock skew).
7.  **Extracts Information:** If all checks pass, it decodes the payload part and gives you back the usable [JWT (JSON Web Token) Object](01_jwt__json_web_token__object_.md) containing all the claims (the traveller's details).

The `JWTDecoder` orchestrates these steps to turn an untrusted string into a verified, usable JWT object containing trustworthy information.

## Using the `JWTDecoder`

Let's decode the JWT string we created in [Chapter 6: JWTEncoder](06_jwtencoder_.md). Remember, we signed it using `HS256` with the secret `"too-short-secret"`.

```java
import io.fusionauth.jwt.JWTDecoder;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.hmac.HMACVerifier; // Our Verifier from Chapter 7
import io.fusionauth.jwt.JWTExpiredException;
import io.fusionauth.jwt.InvalidJWTSignatureException;

// The JWT string we received (copied from Chapter 6 output)
String encodedJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15LWhhYy1rZXktaWQifQ.eyJhdWQiOiJhY2NvdW50LXNlcnZpY2UiLCJleHAiOjE3MDEzNjU5ODMsImlzcyI6Imh0dHBzOi8vbXlhcHAuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLWg3YjJhIiwicm9sZXMiOlsidXNlciIsImJpbGxpbmctYWRtaW4iXX0.tZ1w8_9-r1U2x3t9fJ4iP9c7rA9tW3gI8uG5sD8eE1k";
// NOTE: If you run this much later, the expiration time (exp) in the token might be in the past!

// 1. Prepare the Verifier (must match how the token was signed)
String sharedSecret = "too-short-secret"; // The correct secret!
Verifier hmacVerifier = HMACVerifier.newVerifier(sharedSecret);

// 2. Create a JWTDecoder instance
JWTDecoder decoder = new JWTDecoder();

// 3. Decode and Verify the JWT
try {
    JWT jwt = decoder.decode(encodedJWT, hmacVerifier);

    // 4. If successful, use the claims!
    System.out.println("Successfully decoded JWT!");
    System.out.println("Subject: " + jwt.subject);
    System.out.println("Issuer: " + jwt.issuer);
    System.out.println("Roles: " + jwt.getList("roles"));
    System.out.println("Expiration: " + jwt.expiration);

} catch (JWTExpiredException e) {
    System.err.println("JWT has expired!");
    // Handle expired token (e.g., ask user to log in again)
} catch (InvalidJWTSignatureException e) {
    System.err.println("JWT signature is invalid!");
    // Handle invalid signature (reject the token, log security event)
} catch (Exception e) {
    System.err.println("Error decoding JWT: " + e.getMessage());
    // Handle other potential issues (malformed token, etc.)
}
```

**Explanation:**

1.  We get the `encodedJWT` string we want to inspect.
2.  We create the appropriate [Verifier Interface](07_verifier_interface_.md) (`HMACVerifier`) using the *same secret* that was used to sign the token. This is crucial! If the secret is wrong, verification will fail.
3.  We create an instance of `JWTDecoder`.
4.  We call `decoder.decode(encodedJWT, hmacVerifier)`. This is the main method that performs all the steps: splitting, header decoding, verifier selection, signature check, time checks, and payload decoding.
5.  **Crucially**, we wrap the `decode` call in a `try...catch` block. The `decode` method will throw specific exceptions if validation fails:
    *   `JWTExpiredException`: If the `exp` claim is in the past (considering clock skew).
    *   `InvalidJWTSignatureException`: If the signature doesn't match the data and key.
    *   Other exceptions like `InvalidJWTException` (if the string is malformed) or `MissingVerifierException` (if no suitable verifier is found).
6.  If no exception is thrown, the `decode` method returns the verified [JWT (JSON Web Token) Object](01_jwt__json_web_token__object_.md), and we can safely access its claims (`jwt.subject`, `jwt.getList("roles")`, etc.).

### Handling Multiple Verifiers and Key IDs (`kid`)

Often, the service issuing JWTs might use multiple keys. The JWT header usually includes a `kid` (Key ID) to indicate which key was used. The `JWTDecoder` can handle this easily using a `Map` of verifiers keyed by their `kid`.

```java
import io.fusionauth.jwt.JWTDecoder;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.fusionauth.jwt.rsa.RSAVerifier; // Example for RSA
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
// Assume publicKey1, publicKey2 are loaded PublicKey objects
// Assume secret1 is a byte array or string

// Map Key IDs to their Verifiers
Map<String, Verifier> verifiers = new HashMap<>();
verifiers.put("my-hmac-key-id", HMACVerifier.newVerifier("too-short-secret"));
// verifiers.put("rsa-key-123", RSAVerifier.newVerifier(publicKey1));
// verifiers.put("rsa-key-456", RSAVerifier.newVerifier(publicKey2));

String encodedJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15LWhhYy1rZXktaWQifQ..."; // Same JWT as before

JWTDecoder decoder = new JWTDecoder();
try {
    // Decoder reads 'kid' from header, finds matching Verifier in the map
    JWT jwt = decoder.decode(encodedJWT, verifiers);
    System.out.println("Successfully decoded JWT using kid lookup!");
    System.out.println("Subject: " + jwt.subject);

} catch (Exception e) {
    System.err.println("Error decoding JWT: " + e.getMessage());
}
```

**Explanation:**

*   We create a `Map<String, Verifier>` where the key is the `kid` string and the value is the corresponding `Verifier` instance.
*   When we call `decoder.decode(encodedJWT, verifiers)`, the decoder automatically:
    *   Reads the `kid` from the JWT header (`"my-hmac-key-id"` in our example).
    *   Looks up that `kid` in the provided `verifiers` map.
    *   Uses the found `Verifier` (`HMACVerifier` in this case) to check the signature.
*   This avoids needing to manually check the `kid` yourself.

### Adjusting Clock Skew Tolerance

Network delays and slight clock differences between servers are common. The `JWTDecoder` allows you to configure a tolerance (in seconds) for time checks (`exp`, `nbf`).

```java
import io.fusionauth.jwt.JWTDecoder;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.hmac.HMACVerifier;
// ... other imports

String encodedJWT = "..."; // Your JWT string
Verifier verifier = HMACVerifier.newVerifier("too-short-secret");

// Allow for up to 60 seconds of clock difference
JWTDecoder decoder = new JWTDecoder().withClockSkew(60);

try {
    JWT jwt = decoder.decode(encodedJWT, verifier);
    System.out.println("Decoded with clock skew tolerance.");
    // A token that expired 30 seconds ago would still be accepted.
    // A token whose 'nbf' is 30 seconds in the future would also be accepted.
} catch (Exception e) {
    // ... handle errors ...
}
```

## Under the Hood: The Decoding Process

Let's visualize the steps inside `decoder.decode(encodedJWT, verifier)`:

```mermaid
sequenceDiagram
    participant App as Your Application
    participant Decoder as JWTDecoder Instance
    participant JWTString as Encoded JWT String
    participant Header as Decoded Header Object
    participant Verifier as Verifier Instance
    participant Payload as Decoded Payload Object (JWT)

    App->>Decoder: decode(encodedJWT, verifier)
    Decoder->>JWTString: split(".") -> parts[]
    Decoder->>Decoder: base64Decode(parts[0]) -> headerBytes
    Decoder->>Header: deserialize(headerBytes)
    activate Header
    Header-->>Decoder: return Header object (with alg, kid)
    deactivate Header

    alt Signature Present (parts.length == 3)
        Decoder->>Verifier: canVerify(header.algorithm)
        alt Verifier CAN Verify
            Verifier-->>Decoder: return true
            Decoder->>Decoder: base64Decode(parts[2]) -> signatureBytes
            Decoder->>Decoder: get messageBytes (parts[0] + "." + parts[1])
            Decoder->>Verifier: verify(header.algorithm, messageBytes, signatureBytes)
            activate Verifier
            alt Signature INVALID
                Verifier-->>Decoder: throw InvalidJWTSignatureException
            else Signature VALID
                Verifier-->>Decoder: return (no exception)
            end
            deactivate Verifier
        else Verifier CANNOT Verify
             Verifier-->>Decoder: return false
             Decoder-->>App: throw MissingVerifierException
        end
    else No Signature (parts.length == 2)
        alt Verifier provided OR alg != 'none'
            Decoder-->>App: throw NoneNotAllowedException or MissingSignatureException
        else No Verifier AND alg == 'none'
            Decoder->>Decoder: Proceed (no signature check needed)
        end
    end

    Decoder->>Decoder: base64Decode(parts[1]) -> payloadBytes
    Decoder->>Payload: deserialize(payloadBytes)
    activate Payload
    Payload-->>Decoder: return JWT object (claims)
    deactivate Payload

    Decoder->>Payload: isExpired(now - clockSkew)?
    alt Expired
        Payload-->>Decoder: true
        Decoder-->>App: throw JWTExpiredException
    else Not Expired
        Payload-->>Decoder: false
        Decoder->>Payload: isUnavailableForProcessing(now + clockSkew)?
        alt Not Yet Valid
            Payload-->>Decoder: true
            Decoder-->>App: throw JWTUnavailableForProcessingException
        else Valid Now
            Payload-->>Decoder: false
            Decoder-->>App: return JWT object
        end
    end

```

This diagram shows the detailed flow: splitting the string, decoding the header, finding and using the verifier to check the signature (if present), decoding the payload, performing time checks, and finally returning the JWT object or throwing an exception.

Let's look at some key parts of the `JWTDecoder.java` code:

```java
// From: main/java/io/fusionauth/jwt/JWTDecoder.java
public class JWTDecoder {
  private int clockSkew = 0; // Default clock skew

  // Decode using one or more specific Verifiers (finds first match for alg)
  public JWT decode(String encodedJWT, Verifier... verifiers) {
    // ... null checks ...
    String[] parts = getParts(encodedJWT); // Split into X.Y.Z

    // Decode header first to get algorithm
    Header header = Mapper.deserialize(base64Decode(parts[0]), Header.class);

    // Find the first Verifier that can handle this algorithm
    Verifier verifier = Arrays.stream(verifiers)
                              .filter(v -> v.canVerify(header.algorithm))
                              .findFirst().orElse(null);

    // Determine if 'none' algorithm is allowed (only if no verifiers provided)
    boolean allowNoneAlgorithm = verifiers.length == 0;

    // Call the main validation logic
    return validate(encodedJWT, parts, header, verifier, allowNoneAlgorithm);
  }

  // Decode using a Map of Verifiers looked up by key (e.g., kid)
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers) {
    // Default: use 'kid' header to find the key in the map
    return decode(encodedJWT, verifiers, h -> h.getString("kid"));
  }

  // Method allowing custom function to extract the key from the header
  public JWT decode(String encodedJWT, Map<String, Verifier> verifiers, Function<Header, String> keyFunction) {
     // ... null checks ...
     // Use verifiers::get as the function to lookup Verifier by key
     return decodeJWT(encodedJWT, verifiers::get, keyFunction, verifiers.isEmpty());
  }

  // Internal helper using function to get verifier
  private JWT decodeJWT(String encodedJWT, Function<String, Verifier> verifierFunction, Function<Header, String> keyFunction, boolean allowNoneAlgorithm) {
    String[] parts = getParts(encodedJWT);
    Header header = Mapper.deserialize(base64Decode(parts[0]), Header.class);
    // Apply the custom keyFunction to the header to get the key string
    String key = keyFunction.apply(header);
    // Apply the verifierFunction to the key string to get the Verifier
    Verifier verifier = verifierFunction.apply(key);
    return validate(encodedJWT, parts, header, verifier, allowNoneAlgorithm);
  }


  // Set clock skew tolerance
  public JWTDecoder withClockSkew(int clockSkew) {
    this.clockSkew = clockSkew;
    return this;
  }

  // Helper to split JWT string
  private String[] getParts(String encodedJWT) {
      String[] parts = encodedJWT.split("\\.");
      // Check for 3 parts, or 2 parts where the original string ended with '.'
      // (Handles unsecured JWTs like XXXXX.YYYYY.)
      if (parts.length == 3 || (parts.length == 2 && encodedJWT.endsWith("."))) {
        return parts;
      }
      throw new InvalidJWTException("Expected three part dot separated string.");
  }

  // Helper to decode Base64Url
  private byte[] base64Decode(String string) {
      try {
        return Base64.getUrlDecoder().decode(string);
      } catch (IllegalArgumentException e) {
        throw new InvalidJWTException("Not properly Base64 encoded.", e);
      }
  }

  // Core validation logic
  private JWT validate(String encodedJWT, String[] parts, Header header, Verifier verifier, boolean allowNoneAlgorithm) {
    // --- Signature Checks ---
    if (parts.length == 2) { // No signature part
        if (!allowNoneAlgorithm) throw new NoneNotAllowedException();
        if (header.algorithm != Algorithm.none) throw new MissingSignatureException(...);
        // If we reach here, it's a valid unsecured token (alg:none)
    } else { // Signature part exists (parts.length == 3)
        if (header.algorithm == Algorithm.none) throw new InvalidJWTException("Signature present but alg is none");
        if (verifier == null) throw new MissingVerifierException("No Verifier found for alg: " + header.algorithm);
        if (!verifier.canVerify(header.algorithm)) throw new MissingVerifierException(...); // Double check if looked up by kid

        // Call helper to perform actual signature verification
        verifySignature(verifier, header, parts[2], encodedJWT);
    }

    // --- Decode Payload & Time Checks ---
    JWT jwt = Mapper.deserialize(base64Decode(parts[1]), JWT.class);
    jwt.header = header; // Attach the header to the JWT object
    ZonedDateTime now = now(); // Gets current UTC time

    // Check expiration (exp) allowing for clock skew
    if (jwt.isExpired(now.minusSeconds(clockSkew))) {
      throw new JWTExpiredException();
    }

    // Check not before (nbf) allowing for clock skew
    if (jwt.isUnavailableForProcessing(now.plusSeconds(clockSkew))) {
      throw new JWTUnavailableForProcessingException();
    }

    // All checks passed!
    return jwt;
  }

  // Helper to verify the signature using the Verifier
  private void verifySignature(Verifier verifier, Header header, String signature, String encodedJWT) {
    // Message is Base64(header) + "." + Base64(payload)
    int index = encodedJWT.lastIndexOf('.');
    byte[] message = encodedJWT.substring(0, index).getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = base64Decode(signature);

    // Ask the verifier to check the signature
    verifier.verify(header.algorithm, message, signatureBytes); // Throws if invalid
  }

  // Allows overriding for testing (see TimeMachineJWTDecoder.java)
  protected ZonedDateTime now() {
    return ZonedDateTime.now(ZoneOffset.UTC);
  }
}
```

**Key Points from the Code:**

*   Multiple `decode` methods provide flexibility (pass specific verifiers, or a map keyed by `kid`).
*   `getParts` splits the string and performs basic format validation.
*   The header is always decoded first to determine the `alg` and `kid`.
*   The correct `Verifier` is found either by filtering a list or looking up in a map.
*   The `validate` method centralizes the logic for checking signature requirements (`none` algorithm handling, verifier availability) and time-based claims (`exp`, `nbf`) using the configured `clockSkew`.
*   `verifySignature` isolates the actual call to the `Verifier`'s `verify` method.
*   Exceptions are thrown at the first sign of invalidity (bad format, missing signature, bad signature, expired, not yet valid).
*   If all checks pass, the deserialized `JWT` object is returned.

## Conclusion

Congratulations! You've reached the end of the `fusionauth-jwt` tutorial and learned how the `JWTDecoder` brings everything together to securely process incoming JWTs.

*   You understand that `JWTDecoder` is the **complete inspection station** for JWT strings.
*   It takes the encoded JWT string (`xxxxx.yyyyy.zzzzz`) and one or more [Verifier Interface](07_verifier_interface_.md)s.
*   It **splits** the token, **decodes** the header, selects the right [Verifier Interface](07_verifier_interface_.md), and uses it to **check the signature**.
*   It also validates standard **time claims** (`exp`, `nbf`) with **clock skew** tolerance.
*   If all checks pass, it returns a verified [JWT (JSON Web Token) Object](01_jwt__json_web_token__object_.md); otherwise, it throws specific **exceptions** indicating the failure reason.

With the knowledge gained from these chapters – understanding the [JWT (JSON Web Token) Object](01_jwt__json_web_token__object_.md), choosing an [Algorithm Enum](02_algorithm_enum_.md), handling keys ([PEM Handling](03_pem__privacy_enhanced_mail__handling_.md), [JSONWebKey (JWK) Handling](04_jsonwebkey__jwk__handling_.md)), using the [Signer Interface](05_signer_interface_.md) and [JWTEncoder](06_jwtencoder_.md) to create tokens, and using the [Verifier Interface](07_verifier_interface_.md) and `JWTDecoder` to validate them – you are now well-equipped to work with JSON Web Tokens in your Java applications using the `fusionauth-jwt` library. Happy coding!

---

Generated by [AI Codebase Knowledge Builder](https://github.com/The-Pocket/Tutorial-Codebase-Knowledge)