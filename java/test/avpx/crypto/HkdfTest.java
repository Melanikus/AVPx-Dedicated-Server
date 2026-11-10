package avpx.crypto;

import static avpx.testing.Tests.hex;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsWith;

import java.util.HexFormat;
import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;

// The tests of Hkdf.java: the construction against RFC 5869's own vectors, and the HKDF-SHA-384 version 2 uses against Java 25's own.
// Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// RFC 5869 gives vectors for SHA-256 and SHA-1 only. So the construction (the same code, with its hash as a parameter) is held to the
// RFC's SHA-256 cases, and HKDF-SHA-384 itself to Java 25's own "HKDF-SHA384" (JEP 510), which settles CRYPTO.md section 3's [CHECK]:
// Java 25 has that name. Wycheproof's HKDF-SHA-384 vectors come in with test-vectors/crypto-kat (Secondary's), in their own test.
public final class HkdfTest {
  private HkdfTest() {
  }

  private static byte[] h(String hex) {
    return HexFormat.of().parseHex(hex);
  }

  public static void register() {
    // RFC 5869 appendix A (rfc5869.txt, sha256 7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c, as PO fetched it)
    test("HKDF by hand gives RFC 5869's own answers (its SHA-256 cases 1 and 2), and refuses case 3's missing salt by its words", () -> {
      same(hex(Hkdf.hmac("HmacSHA256", h("000102030405060708090a0b0c"), h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))),
          "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "case 1's PRK");
      same(hex(Hkdf.derive("HmacSHA256", 32, h("000102030405060708090a0b0c"), h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
          h("f0f1f2f3f4f5f6f7f8f9"), 42)), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
          "case 1's OKM");

      String ikm2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
          + "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
      String salt2 = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
          + "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
      String info2 = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
          + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
      same(hex(Hkdf.hmac("HmacSHA256", h(salt2), h(ikm2))), "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
          "case 2's PRK");
      same(hex(Hkdf.derive("HmacSHA256", 32, h(salt2), h(ikm2), h(info2), 82)),
          "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
              + "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87", "case 2's OKM, longer than two blocks");

      // Case 3 has no salt, which RFC 5869 reads as a salt of all zeros. Version 2 never has no salt (the top of Hkdf.java says why),
      // so ours refuses it, every way in: HMAC alone, the whole of HKDF, and Expand from a key of no bytes
      throwsWith(() -> Hkdf.hmac("HmacSHA256", h(""), h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")), Hkdf.NO_KEY,
          "case 3's PRK: no salt is refused");
      throwsWith(() -> Hkdf.derive("HmacSHA256", 32, h(""), h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), h(""), 42), Hkdf.NO_KEY,
          "case 3's OKM: no salt is refused");
      throwsWith(() -> Hkdf.derive(h(""), h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), h(""), 42), Hkdf.NO_KEY,
          "HKDF-SHA-384 with no salt is refused too");
      throwsWith(() -> Hkdf.expand(h(""), h(""), 42), Hkdf.NO_KEY, "Expand from a key of no bytes is refused");
    });

    test("Java 25 has HKDF-SHA384 (CRYPTO.md's [CHECK]), and it gives the same bytes as HKDF by hand", () -> {
      KDF kdf = KDF.getInstance("HKDF-SHA384");
      byte[] salt = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
      byte[] ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
      byte[] info = h("f0f1f2f3f4f5f6f7f8f9");

      for (int length : new int[] {32, 48, 80, 88, 200}) {
        byte[] java = kdf.deriveData(HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt).thenExpand(info, length));
        same(hex(Hkdf.derive(salt, ikm, info, length)), hex(java), length + " bytes");
      }
    });

    test("HKDF refuses to make more than 255 blocks of its hash", () -> {
      byte[] prk = new byte[48];
      same(Hkdf.expand(prk, new byte[0], 255 * 48).length, 255 * 48, "255 blocks");
      avpx.testing.Tests.throwsAny(() -> Hkdf.expand(prk, new byte[0], 255 * 48 + 1), "one byte more");
    });
  }
}
