package analyzers

import (
	"github.com/1047261438/cryptogo/run"
	"github.com/1047261438/cryptogo/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

var WeakcryptoAnalyzer = &analysis.Analyzer{
	Name:     "weak_crypto",
	Doc:      "reports when some weak cryptographic algorithms are used",
	Run:      weakcryptoRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// weakcryptoFuncs01() returns a map of functions that weakcryptos are used
func weakcryptoFuncs01() (map[string][]string, map[string]string) {
	return map[string][]string{
			"crypto/des": {"NewCipher"},
			"crypto/rc4": {"NewCipher"},
			"golang.org/x/crypto/md4": {"New", "Sum"},
			"crypto/md5": {"New", "Sum"},
			"crypto/sha1": {"New", "Sum"},
			//"math/rand": {"Seed"},


			"golang.org/x/crypto/blowfish": {"NewCipher"},
			"golang.org/x/crypto/cast5": {"NewCipher"},
			"golang.org/x/crypto/tea": {"NewCipher", "NewCipherWithRounds"},
			"golang.org/x/crypto/xtea": {"NewCipher"},
			"golang.org/x/crypto/ripemd160": {"New"},
			"golang.org/x/crypto/bn256": {"G1", "G2", "GT"},


			"crypto/rsa": {"EncryptPKCS1v15"},


	} , map[string]string{
			"crypto/des": "DES - NIST Withdraws Outdated Data Encryption Standard",
			"crypto/rc4": "RC4 - RFC 7465 - Prohibiting RC4 Cipher Suites",
			"golang.org/x/crypto/md4": "MD4 - RFC 6150 - MD4 to Historic Status",
			"crypto/md5": "MD5 - RFC 9155 - Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2 and DTLS 1.2",
			"crypto/sha1":"SHA-1 - RFC 9155 - Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2 and DTLS 1.2",

			//"math/rand": "math/rand might be easily predictable regardless ",

			"golang.org/x/crypto/blowfish": "blowfish - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"golang.org/x/crypto/cast5": "CAST5 - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"golang.org/x/crypto/tea": "TEA - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"golang.org/x/crypto/xtea": "XTEA - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"crypto/ripemd160": "RIPEMD-160 - Mendel et al. On the Collision Resistance of RIPEMD-160 *",
			"golang.org/x/crypto/bn256":"bn256 - This package is frozen, and not implemented in constant time.",

			"crypto/rsa": "RSAES-PKCS1-v1_5 is deprecated, RSAES-OAEP is recommended， that is, \"EncryptOAEP\"",

		}
}
// weakcryptoFuncs23() returns a map of functions that weakcryptos are used
func weakcryptoFuncs23() (map[string][]string, map[string]string) {
	return map[string][]string{
			"golang.org/x/crypto/twofish": {"NewCipher"},
			"crypto/rsa": {"SignPKCS1v15"},
			"golang.org/x/crypto/curve25519": {"ScalarMult"},
			"golang.org/x/crypto/pkcs12": {"Decode", "ToPEM"},
			"golang.org/x/crypto/poly1305": {"Sum", "Verify"},
			"golang.org/x/crypto/chacha20": {"HChaCha20"},

			"crypto/des": {"NewTripleDESCipher"},
			"crypto/sha256": {"New224", "Sum224"},
			"crypto/sha512": {"New512_224", "Sum512_224"},
			"golang.org/x/crypto/sha3": {"New224", "Sum224"},
	} , map[string]string{
			"golang.org/x/crypto/twofish": "Twofish - Acceptable but not recommended cryptographic algorithms.",
			"crypto/rsa": "RSASSA-PKCS1-v1_5 is deprecated, RSASSA-PSS is recommended， that is, \"SignPSS\"",
			"golang.org/x/crypto/curve25519": "ScalarMult is deprecated",
			"golang.org/x/crypto/pkcs12": "Package pkcs12 is deprecated",
			"golang.org/x/crypto/poly1305": "Poly1305 is deprecated",
			"golang.org/x/crypto/chacha20": "chacha20 - Do not use chacha20 encryption, chacha20poly1305 is recommended.",

			"crypto/des": "3TDEA",
			"crypto/sha256": "SHA-224 - NIST 800-57 : In 2031 and beyond, SHA-224 shall not be used for applying cryptographic protection.",
			"crypto/sha512": "SHA-512/224 - NIST 800-57 : In 2031 and beyond, SHA-512/224 shall not be used for applying cryptographic protection.",
			"golang.org/x/crypto/sha3": "SHA3-224 - NIST 800-57 : In 2031 and beyond, SHA3-224 shall not be used for applying cryptographic protection.",

		}
}


// weakcryptoRun runs the weakcrypto analyzer
func weakcryptoRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Creates call graph of function calls
	cg := make(util.CallGraph)

	// Fills in call graph
	if !run.CGFlat {
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
	weak01, wOutput := weakcryptoFuncs01()
	for _, output := range wOutput{
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}

	// Iterate over every specified vulnerable package
	for pkg, funcs := range weak01 {
		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {
			// Construct full name of function
			current_function := pkg + "." + fn
			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] {

				message := "Danger: " // Prohibited to use
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				results = append(results, util.MakeFinding(message, targetFunc, nil, wOutput[pkg]))
			}
		}
	}

	//***********************************************************************************************************************

	// Grabs vulnerable functions to scan for
	weakcryptofuncs23, wOutput23 := weakcryptoFuncs23()
	for _, output := range wOutput23{
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}

	for pkg, funcs := range weakcryptofuncs23 {
		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {
			// Construct full name of function
			current_function := pkg + "." + fn
			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] {

				message := "Danger: " // Not recommended
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				results = append(results, util.MakeFinding(message, targetFunc, nil, wOutput23[pkg]))
			}
		}
	}

	return results, nil
}