package avpx.list;

import avpx.relay.Crypto;
import avpx.relay.RandomBytes;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

// The list's certificate and its private key, from the two PEM files certbot keeps (deploy/certificate-hook.sh copies them where the
// server can read them), made into what Java's TLS uses. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// - Each file is opened once and read through that one handle, at most MOST_FILE_BYTES, so what's checked is what's used.
// - The certificate file is the certificate and its chain, as certbot's fullchain.pem holds them.
// - The key file is the private key in PKCS#8 form (-----BEGIN PRIVATE KEY-----), EC or RSA, as certbot writes it. An older form, or an
//   encrypted key, is refused with a plain reason that says how to make the PKCS#8 one.
// - The key must belong to the certificate: it signs a few random bytes, and the certificate's public key must check that signature,
//   before the pair is used. A pair that doesn't match is refused, so a half-renewed pair can't take the list down.
// The key never leaves the machine and is never written anywhere by this. The words of a CertificateProblem never hold the key's bytes.
final class Certificates {
  private Certificates() {
  }

  private static final int MOST_FILE_BYTES = 64 * 1024;
  private static final String KEY_START = "-----BEGIN PRIVATE KEY-----";
  private static final String KEY_END = "-----END PRIVATE KEY-----";
  private static final int CHECK_BYTES = 32;

  // A pair that's been checked and can be used, with the bytes it was made from, so a later look can tell if the files changed
  record Loaded(SSLContext context, byte[] certBytes, byte[] keyBytes) {
    boolean sameFiles(byte[] cert, byte[] key) {
      return Arrays.equals(certBytes, cert) && Arrays.equals(keyBytes, key);
    }
  }

  // A file's bytes, through one handle, at most MOST_FILE_BYTES
  static byte[] readFile(Path file) throws ListServer.CertificateProblem {
    try (InputStream in = Files.newInputStream(file)) {
      byte[] bytes = in.readNBytes(MOST_FILE_BYTES + 1);

      if (bytes.length > MOST_FILE_BYTES) {
        throw new ListServer.CertificateProblem("a file is over 64 KB, which no certificate or key is");
      }

      return bytes;
    } catch (IOException e) {
      throw new ListServer.CertificateProblem("a file could not be read (" + e.getClass().getSimpleName() + ")");
    }
  }

  static Loaded load(Path certFile, Path keyFile) throws ListServer.CertificateProblem {
    return load(readFile(certFile), readFile(keyFile));
  }

  static Loaded load(byte[] certBytes, byte[] keyBytes) throws ListServer.CertificateProblem {
    try {
      List<X509Certificate> chain = new ArrayList<>();

      for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(certBytes))) {
        if (c instanceof X509Certificate x509) {
          chain.add(x509);
        }
      }

      if (chain.isEmpty()) {
        throw new ListServer.CertificateProblem("the certificate file has no certificate in it");
      }

      PrivateKey key = privateKey(keyBytes);
      checkPair(key, chain.get(0));

      // Java's TLS takes a key and its chain from a key store: this one is made here, in memory only, with a password nobody needs to know
      char[] password = Crypto.hex(RandomBytes.secure().next(16)).toCharArray();
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      store.setKeyEntry("list", key, password, chain.toArray(new X509Certificate[0]));
      KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keys.init(store, password);
      Arrays.fill(password, '0');
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(keys.getKeyManagers(), null, null);
      return new Loaded(context, certBytes.clone(), keyBytes.clone());
    } catch (GeneralSecurityException | IOException e) {
      throw new ListServer.CertificateProblem("the certificate or key isn't one Java can use (" + e.getClass().getSimpleName() + ")");
    }
  }

  // The private key, from its PKCS#8 PEM text
  private static PrivateKey privateKey(byte[] keyBytes) throws ListServer.CertificateProblem, GeneralSecurityException {
    String text = new String(keyBytes, StandardCharsets.US_ASCII);

    if (text.contains("ENCRYPTED PRIVATE KEY")) {
      throw new ListServer.CertificateProblem("the key is encrypted; the server needs it as certbot writes it, unencrypted");
    }

    int start = text.indexOf(KEY_START);
    int end = text.indexOf(KEY_END);

    if (start < 0 || end < start || text.indexOf(KEY_START, start + 1) >= 0) {
      throw new ListServer.CertificateProblem("the key file must hold one key in PKCS#8 form (" + KEY_START + "); "
          + "openssl pkcs8 -topk8 -nocrypt -in <key> makes it from an older form");
    }

    String base64 = text.substring(start + KEY_START.length(), end).replace("\r", "").replace("\n", "");
    byte[] der;

    try {
      der = Base64.getDecoder().decode(base64);
    } catch (IllegalArgumentException e) {
      throw new ListServer.CertificateProblem("the key file's key isn't base64");
    }

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
    Arrays.fill(der, (byte) 0);

    // An EC key (certbot's own choice since 2.0) or an RSA one: whichever reads it
    for (String algorithm : List.of("EC", "RSA")) {
      try {
        return KeyFactory.getInstance(algorithm).generatePrivate(spec);
      } catch (GeneralSecurityException e) {
        // not this kind: try the next
      }
    }

    throw new ListServer.CertificateProblem("the key is neither an EC nor an RSA key");
  }

  // That the key belongs to the certificate: what it signs, the certificate's public key checks
  private static void checkPair(PrivateKey key, X509Certificate certificate) throws ListServer.CertificateProblem, GeneralSecurityException {
    String algorithm = switch (key.getAlgorithm()) {
      case "EC" -> "SHA256withECDSA";
      case "RSA" -> "SHA256withRSA";
      default -> throw new ListServer.CertificateProblem("the key is neither an EC nor an RSA key");
    };

    byte[] check = RandomBytes.secure().next(CHECK_BYTES);
    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(key);
    signer.update(check);
    byte[] signature = signer.sign();
    Signature checker = Signature.getInstance(algorithm);
    checker.initVerify(certificate.getPublicKey());
    checker.update(check);

    if (!checker.verify(signature)) {
      throw new ListServer.CertificateProblem("the key doesn't belong to the certificate");
    }
  }
}
