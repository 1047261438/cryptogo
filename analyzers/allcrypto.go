package analyzers

import (
	"github.com/1047261438/cryptogo/run"
	"github.com/1047261438/cryptogo/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

var AllcryptoAnalyzer = &analysis.Analyzer{
	Name:     "all_crypto",
	Doc:      "reports all cryptographic algorithms",
	Run:      allcryptoRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// allcryptoFuncs() returns a map of functions that weakcryptos are used
func allcryptoFuncs() (map[string][]string, map[string]string) {
	return map[string][]string{
			"crypto/des": {"NewCipher", "NewTripleDESCipher"},
			"crypto/rc4": {"NewCipher"},
			"golang.org/x/crypto/md4": {"New", "Sum"},
			"crypto/md5": {"New", "Sum"},
			"crypto/sha1": {"New", "Sum"},

			"golang.org/x/crypto/blowfish": {"NewCipher"},
			"golang.org/x/crypto/cast5": {"NewCipher"},
			"golang.org/x/crypto/tea": {"NewCipher", "NewCipherWithRounds"},
			"golang.org/x/crypto/twofish": {"NewCipher"},
			"golang.org/x/crypto/xtea": {"NewCipher"},
			"crypto/sha256": {"New224", "Sum224", "New", "Sum256"},
			"crypto/sha512": {"New", "Sum512", "New384", "Sum384", "New512_224", "Sum512_224", "New512_256", "Sum512_256"},
			"golang.org/x/crypto/sha3": {"New224", "Sum224", "New256", "New384", "New512",  "Sum256", "Sum384", "Sum512",
			"NewLegacyKeccak256", "NewLegacyKeccak512", "ShakeSum128", "ShakeSum256"},
			"golang.org/x/crypto/ripemd160": {"New"},

			"crypto/cipher": {"NewCBCEncrypter", "NewCFBEncrypter","NewOFB", "NewCTR", "NewGCM"},
			"golang.org/x/crypto": {"NewCipher"},
			"crypto/rsa": {"GenerateKey", "SignPKCS1v15", "EncryptPKCS1v15", "EncryptOAEP", "SignPSS"},
			"crypto/elliptic": {"P224", "P256", "P384", "P512"},
			"golang.org/x/crypto/bn256": {"G1", "G2", "GT"},
			"golang.org/x/crypto/argon2": {"Key", "IDKey"},
			"golang.org/x/crypto/bcrypt": {"GenerateFromPassword", "newFromHash", "bcrypt"},
			"golang.org/x/crypto/hkdf": {"Extract", "New"},
			"golang.org/x/crypto/pbkdf2": {"Key"},
			"golang.org/x/crypto/scrypt": {"Key"},

			"crypto/aes": {"NewCipher"},
			"crypto/dsa": {"GenerateParameters"},
			"crypto/ecdsa": {"GenerateKey"},
			"crypto/hmac": {"New"},

			"crypto/ed25519": {"GenerateKey"},
			"golang.org/x/crypto/ed25519": {"GenerateKey"},
			"golang.org/x/crypto/blake2b": {"New", "New256", "New384", "New512", "Sum256", "Sum384", "Sum512"},
			"golang.org/x/crypto/blake2s": {"New128", "New256", "Sum256"},
			"golang.org/x/crypto/chacha20": {"HChaCha20"},
			"golang.org/x/crypto/chacha20poly1305": {"New", "NewX"},
			"golang.org/x/crypto/curve25519": {"ScalarBaseMult", "ScalarMult", "X25519"},
			"golang.org/x/crypto/pkcs12": {"Decode", "ToPEM"},
			"golang.org/x/crypto/poly1305": {"Sum", "Verify"},
			"golang.org/x/crypto/salsa20": {"XORKeyStream"},
			"golang.org/x/crypto/xts": {"NewCipher"},
			"golang.org/x/crypto/internal/poly1305": {"Sum", "Verify"},

		} , map[string]string{
			"crypto/des": "NIST Withdraws Outdated Data Encryption Standard - DES",
			"crypto/rc4": "RFC 7465 - Prohibiting RC4 Cipher Suites",
			"golang.org/x/crypto/md4": "RFC 6150 - MD4 to Historic Status",
			"crypto/md5": "RFC 9155 - Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2 and DTLS 1.2 - MD5",
			"crypto/sha1":"RFC 9155 - Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2 and DTLS 1.2 - SHA-1",

			"golang.org/x/crypto/blowfish": "Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN - blowfish",
			"golang.org/x/crypto/cast5": "Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN - CAST5",
			"golang.org/x/crypto/tea": "Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN - TEA",
			"golang.org/x/crypto/twofish": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm - Twofish",
			"golang.org/x/crypto/xtea": "Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN - XTEA",
			"crypto/sha256": "SHA-224 or SHA-256",
			"crypto/sha512": "SHA-384 or SHA-512/224 or SHA-512/256 or SHA-512",
			"golang.org/x/crypto/sha3": "NIST 800-57 : In 2031 and beyond, SHA3-224 shall not be used for applying cryptographic protection.",
			"crypto/ripemd160": "Mendel et al. On the Collision Resistance of RIPEMD-160 *",

			"crypto/cipher": "CBC/CFB/OFB/CTR",
			"golang.org/x/crypto": "XTS",
			"crypto/rsa": "RSA-Padding5",
			"crypto/elliptic":"Elliptic P-224 or P-256 or P-384",
			"golang.org/x/crypto/bn256":"The package bn256 is frozen, and not implemented in constant time.",
			"golang.org/x/crypto/argon2": "Using Argon2",
			"golang.org/x/crypto/bcrypt": "Using Bcrypt",
			"golang.org/x/crypto/hkdf": "Using HKDF",
			"golang.org/x/crypto/pbkdf2": "Using PBKDF2",
			"golang.org/x/crypto/scrypt": "Using scrypt",
			
			"crypto/aes": "Using AES",
			"crypto/dsa": "Using DSA",
			"crypto/ecdsa": "Using ECDSA",
			"crypto/hmac": "Using HMAC",

			"crypto/ed25519": "Using ED25519",
			"golang.org/x/crypto/ed25519": "Using ED25519",
			"golang.org/x/crypto/blake2b": "Using BLAKE2b",
			"golang.org/x/crypto/blake2s": "Using BLAKE2s",
			"golang.org/x/crypto/chacha20": "Using Chacha20",
			"golang.org/x/crypto/chacha20poly1305": "Using Chacha20Poly1305",
			"golang.org/x/crypto/curve25519": "ScalarMult is deprecated",
			"golang.org/x/crypto/pkcs12": "Package pkcs12 is frozen",
			"golang.org/x/crypto/poly1305": "Poly1305 is deprecated",
			"golang.org/x/crypto/salsa20": "Using Salsa20",
			"golang.org/x/crypto/xts": "Using XTS",
			"golang.org/x/crypto/internal/poly1305": "Using Poly1305",
		}
}

// allcryptoRun runs the weakcrypto analyzer
func allcryptoRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Creates call graph of function calls
	cg := make(util.CallGraph)

	// Fills in call graph
	if !run.CGFlat {	//wening
		// Builds SSA model of Go code
		ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

		for _, fn := range ssa_functions {
			cg.AnalyzeFunctionO(fn)
		}
		run.CG = cg
	} else {
		cg = run.CG
	}

	//util.Cwelist = make(map[string]bool)

	// Grabs vulnerable functions to scan for
	all, wOutput := allcryptoFuncs()
	for _, output := range wOutput{
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}

	// Iterate over every specified vulnerable package
	for pkg, funcs := range all {
		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {
			// Construct full name of function
			current_function := pkg + "." + fn
			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] {

				message := "all use "
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				results = append(results, util.MakeFinding(message, targetFunc, nil, wOutput[pkg]))
			}
		}
	}
	return results, nil
}