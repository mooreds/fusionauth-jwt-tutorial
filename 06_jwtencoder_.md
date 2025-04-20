# Chapter 6: JWTEncoder

In the [previous chapter](05_signer_interface_.md), we learned about the `Signer` interface – the specialized "sealing machine" that uses a secret or private key to create a digital signature based on a chosen algorithm. We now have our passport data ([JWT (JSON Web Token) Object](01_jwt__json_web_token__object_.md)) and the official signing tool ([Signer Interface](05_signer_interface_.md)).

But how do we assemble everything into the final, compact, and secure format that we can actually send around? We need a final step: the **lamination process**.

## The Lamination Machine: What is the JWTEncoder?

Think back to our passport analogy. You have the paper pages with your information (`JWT` object) and the official seal stamp (`Signer`). The `JWTEncoder` is like the **lamination machine** at the passport office. It takes all the pieces, puts them together in the correct order, applies the final security features (the signature), and seals it all into a durable, tamper-evident, and easy-to-carry format.

Specifically, the `JWTEncoder` takes:

1.  Your `JWT` object (containing the claims/payload).
2.  A configured `Signer` (which knows the algorithm and holds the necessary key/secret).

And it produces the **final JWT string**, which looks like `xxxxx.yyyyy.zzzzz`. This string is URL-safe, meaning you can easily include it in web addresses or HTTP headers.

Here's the assembly process performed by the `JWTEncoder`:

1.  **Prepare Header:** Creates the JSON header, making sure the `alg` (algorithm) field matches the one provided by the `Signer`. It might also add a `kid` (Key ID) from the `Signer`.
2.  **Serialize & Encode Header:** Converts the header JSON object into a JSON string, then encodes it using Base64Url encoding (this becomes the `xxxxx` part).
3.  **Serialize & Encode Payload:** Converts the `JWT` object (your claims) into a JSON string, then encodes it using Base64Url encoding (this becomes the `yyyyy` part).
4.  **Create Signature Input:** Joins the encoded header and encoded payload with a single dot (`.`) in between (e.g., `xxxxx.yyyyy`).
5.  **Generate Signature:** Passes this combined string to the `Signer`'s `sign()` method. The `Signer` uses its internal key/secret and algorithm to generate the raw signature bytes.
6.  **Encode Signature:** Encodes the raw signature bytes using Base64Url encoding (this becomes the `zzzzz` part).
7.  **Assemble Final Token:** Joins the encoded header, encoded payload, and encoded signature with dots (`.`).

The result is the familiar, compact JWT string: `xxxxx.yyyyy.zzzzz`.

## Using the `JWTEncoder`

Let's see how to use the `JWTEncoder` to create a signed JWT string. We'll use the `HMACSigner` from the previous chapter's example.

```java
import io.fusionauth.jwt.JWTEncoder;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.hmac.HMACSigner; // From Chapter 5 example
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

// 1. Prepare the JWT Payload (from Chapter 1)
JWT jwt = new JWT()
    .setIssuer("https://myapp.example.com")
    .setSubject("user-h7b2a")
    .setAudience("account-service")
    .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusHours(1))
    .addClaim("roles", new String[]{"user", "billing-admin"});

// 2. Prepare the Signer (from Chapter 5)
String sharedSecret = "too-short-secret"; // Use a strong secret in reality!
String keyId = "my-hmac-key-id";
Signer hmacSigner = HMACSigner.newSHA256Signer(sharedSecret, keyId);

// 3. Create a JWTEncoder instance
JWTEncoder encoder = new JWTEncoder();

// 4. Encode the JWT using the Signer
String encodedJWT = encoder.encode(jwt, hmacSigner);

// 5. Print the result!
System.out.println("Encoded JWT:");
System.out.println(encodedJWT);
```

**Explanation:**

1.  We create our `JWT` object with the claims we want to include (the passport data).
2.  We create our `Signer` instance (`HMACSigner` in this case) configured with the correct algorithm (`HS256`), secret, and optional Key ID (`kid`).
3.  We create a new instance of `JWTEncoder`. It's usually stateless, so one instance can be reused.
4.  We call the `encoder.encode(jwt, hmacSigner)` method. This is where the magic happens! The encoder performs the 7 steps described earlier (serialize, encode, sign, assemble).
5.  The method returns the final, compact JWT string.

**Example Output (will vary slightly due to timestamps):**

```
Encoded JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15LWhhYy1rZXktaWQifQ.eyJhdWQiOiJhY2NvdW50LXNlcnZpY2UiLCJleHAiOjE3MDEzNjU5ODMsImlzcyI6Imh0dHBzOi8vbXlhcHAuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLWg3YjJhIiwicm9sZXMiOlsidXNlciIsImJpbGxpbmctYWRtaW4iXX0.tZ1w8_9-r1U2x3t9fJ4iP9c7rA9tW3gI8uG5sD8eE1k
```

You can see the three parts separated by dots:

*   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15LWhhYy1rZXktaWQifQ` (Base64Url encoded header)
*   `eyJhdWQiOiJhY2NvdW50LXNlcnZpY2UiLCJleHAiOjE3MDEzNjU5ODMsImlzcyI6Imh0dHBzOi8vbXlhcHAuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLWg3YjJhIiwicm9sZXMiOlsidXNlciIsImJpbGxpbmctYWRtaW4iXX0` (Base64Url encoded payload)
*   `tZ1w8_9-r1U2x3t9fJ4iP9c7rA9tW3gI8uG5sD8eE1k` (Base64Url encoded signature)

**(Self-Study Tip):** Go to a website like [jwt.io](https://jwt.io/) and paste the generated token. It will decode the header and payload for you (it won't be able to verify the signature without the secret). You'll see the `alg` and `kid` in the header, and your claims in the payload.

## Under the Hood: The Encoding Process

Let's visualize the steps inside the `encoder.encode(jwt, signer)` call:

```mermaid
sequenceDiagram
    participant App as Your Application
    participant Encoder as JWTEncoder Instance
    participant Header as Header Object
    participant JWTPayload as JWT Object (Payload)
    participant JsonMapper as Internal JSON Mapper
    participant Base64Url as Base64Url Encoder
    participant Signer as Signer Instance (e.g., HMACSigner)

    App->>Encoder: encode(jwtPayload, signer)
    Encoder->>Header: new Header()
    Encoder->>Signer: getAlgorithm()
    Signer-->>Encoder: return Algorithm (e.g., HS256)
    Encoder->>Header: set algorithm = HS256
    Encoder->>Signer: getKid() (Optional)
    Signer-->>Encoder: return kid (e.g., "my-hmac-key-id")
    Encoder->>Header: set kid = "my-hmac-key-id"

    Encoder->>JsonMapper: serialize(header)
    JsonMapper-->>Encoder: return headerJsonString
    Encoder->>Base64Url: encode(headerJsonString)
    Base64Url-->>Encoder: return encodedHeader ("xxxxx")

    Encoder->>JsonMapper: serialize(jwtPayload)
    JsonMapper-->>Encoder: return payloadJsonString
    Encoder->>Base64Url: encode(payloadJsonString)
    Base64Url-->>Encoder: return encodedPayload ("yyyyy")

    Encoder->>Encoder: Combine: dataToSign = encodedHeader + "." + encodedPayload
    Encoder->>Signer: sign(dataToSign)
    Signer-->>Encoder: return signatureBytes

    Encoder->>Base64Url: encode(signatureBytes)
    Base64Url-->>Encoder: return encodedSignature ("zzzzz")

    Encoder->>Encoder: Combine final: encodedHeader + "." + encodedPayload + "." + encodedSignature
    Encoder-->>App: return finalJwtString ("xxxxx.yyyyy.zzzzz")
```

This diagram shows the flow: getting algorithm/kid from the signer, serializing/encoding header and payload, combining them, asking the signer to sign, encoding the signature, and finally joining all three parts.

Now let's look at the `JWTEncoder.java` code:

```java
// From: main/java/io/fusionauth/jwt/JWTEncoder.java
public class JWTEncoder {

  // Main encode method we used
  public String encode(JWT jwt, Signer signer) {
    // Default behavior: add the signer's 'kid' to the header if available
    return encode(jwt, signer, h -> {
      try {
        String kid = signer.getKid();
        if (kid != null) {
          h.set("kid", kid); // Add 'kid' to Header object 'h'
        }
      } catch (UnsupportedOperationException ignore) {
        // Ignore if signer doesn't support getKid()
      }
    });
  }

  // Overloaded encode method allowing custom header modifications
  public String encode(JWT jwt, Signer signer, Consumer<Header> consumer) {
      Header header = new Header();
      if (consumer != null) {
          consumer.accept(header); // Apply custom header changes (like adding 'kid')
      }
      return encodeInternal(jwt, signer, header); // Call the private helper
  }


  // Private helper method doing the main work
  private String encodeInternal(JWT jwt, Signer signer, Header header) {
    Objects.requireNonNull(jwt);    // Ensure JWT is not null
    Objects.requireNonNull(signer); // Ensure Signer is not null

    List<String> parts = new ArrayList<>(3); // List to hold the 3 parts

    // Step 1: Set the 'alg' in the header (MUST come from the signer)
    header.algorithm = signer.getAlgorithm();

    // Step 2: Serialize & Encode Header
    byte[] headerBytes = Mapper.serialize(header); // Uses internal Jackson Mapper
    parts.add(base64Encode(headerBytes));          // Add "xxxxx" to list

    // Step 3: Serialize & Encode Payload
    byte[] payloadBytes = Mapper.serialize(jwt);   // Uses internal Jackson Mapper
    parts.add(base64Encode(payloadBytes));         // Add "yyyyy" to list

    // Step 4: Create Signature Input
    String dataToSign = String.join(".", parts); // Join "xxxxx" and "yyyyy"

    // Step 5: Generate Signature
    byte[] signature = signer.sign(dataToSign);    // Ask the signer to sign

    // Step 6: Encode Signature
    parts.add(base64Encode(signature));            // Add "zzzzz" to list

    // Step 7: Assemble Final Token
    return String.join(".", parts);                // Join all 3 parts with dots
  }

  // Helper for Base64Url encoding (no padding)
  private String base64Encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
```

**Key Points from the Code:**

*   The public `encode` methods provide convenience, often setting the `kid` header automatically from the `Signer`. They delegate to the private `encodeInternal` method.
*   `encodeInternal` strictly follows the assembly process outlined before.
*   It relies on an internal `Mapper` (using the Jackson library) to convert the `Header` and `JWT` objects to JSON byte arrays.
*   It uses the standard Java `Base64.getUrlEncoder().withoutPadding()` for correct Base64Url encoding.
*   Crucially, it calls the `signer.sign()` method, passing the `encodedHeader + "." + encodedPayload` string.
*   Finally, it joins the three Base64Url encoded parts using `String.join(".", parts)`.

## Conclusion

You've successfully learned how the `JWTEncoder` acts as the final assembly line and lamination machine for creating JWTs!

*   It takes the passport data ([JWT (JSON Web Token) Object](01_jwt__json_web_token__object_.md)) and the sealing tool ([Signer Interface](05_signer_interface_.md)).
*   It meticulously **serializes**, **Base64Url encodes**, and **joins** the header, payload, and signature parts.
*   It uses the provided `Signer` to generate the crucial **signature** that ensures the token's integrity.
*   The final output is the compact, URL-safe **JWT string** (`xxxxx.yyyyy.zzzzz`).

Now that we can create secure JWTs, the next logical step is to learn how to *verify* them when we receive them from others. How can we check the signature and ensure the token is valid and hasn't been tampered with? That requires a `Verifier`.

Next: [Chapter 7: Verifier Interface](07_verifier_interface_.md)

---

Generated by [AI Codebase Knowledge Builder](https://github.com/The-Pocket/Tutorial-Codebase-Knowledge)