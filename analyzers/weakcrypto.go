/*wening —— weakcrypto*/
package analyzers

import (
	"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"strings"
)

var WeakcryptoAnalyzer = &analysis.Analyzer{
	Name:     "weak_crypto",
	Doc:      "reports when some weak cryptographic algorithms are used",
	Run:      weakcryptoRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// weakcryptoFuncs01() returns a map of functions that weakcryptos are used
func weakcryptoFuncs01() (map[string][]string, map[string]string) {	//写map是因为它不按顺序输出，只能查找键。。。
	return map[string][]string{	//函数名
			"crypto/des": {"NewCipher"},	//还需要考虑一下des和3des怎么区分, "NewTripleDESCipher"
			"crypto/rc4": {"NewCipher"},
			"golang.org/x/crypto/md4": {"New", "Sum"},
			"crypto/md5": {"New", "Sum"},
			"crypto/sha1": {"New", "Sum"},
			"math/crypto": {"Seed"},


			"golang.org/x/crypto/blowfish": {"NewCipher"},
			"golang.org/x/crypto/cast5": {"NewCipher"},
			"golang.org/x/crypto/tea": {"NewCipher", "NewCipherWithRounds"},
			"golang.org/x/crypto/xtea": {"NewCipher"},
			"golang.org/x/crypto/ripemd160": {"New"},
			"golang.org/x/crypto/bn256": {"G1", "G2", "GT"},	//弃用


			"crypto/rsa": {"EncryptPKCS1v15"},


	} , map[string]string{	//警告信息
			"crypto/des": "0 - DES - NIST Withdraws Outdated Data Encryption Standard",
			"crypto/rc4": "0 - RC4 - RFC 7465 - Prohibiting RC4 Cipher Suites",
			"golang.org/x/crypto/md4": "0 - MD4 - RFC 6150 - MD4 to Historic Status",
			"crypto/md5": "0 - MD5 - RFC 9155 - Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2 and DTLS 1.2",
			"crypto/sha1":"0 - SHA-1 - RFC 9155 - Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2 and DTLS 1.2",

			"math/crypto": "math/crypto",

			"golang.org/x/crypto/blowfish": "1 - blowfish - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"golang.org/x/crypto/cast5": "1 - CAST5 - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"golang.org/x/crypto/tea": "1 - TEA - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"golang.org/x/crypto/xtea": "1 - XTEA - Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN",
			"crypto/ripemd160": "1 - RIPEMD-160 - Mendel et al. On the Collision Resistance of RIPEMD-160 *",
			"golang.org/x/crypto/bn256":"1 - bn256 - This package is frozen, and not implemented in constant time.",

			"crypto/rsa": "2 - RSAES-PKCS1-v1_5 is deprecated, RSAES-OAEP is recommended， that is, \"EncryptOAEP\"",

		}
}
// weakcryptoFuncs23() returns a map of functions that weakcryptos are used
func weakcryptoFuncs23() (map[string][]string, map[string]string) {
	return map[string][]string{
			"golang.org/x/crypto/twofish": {"NewCipher"},
			"crypto/rsa": {"SignPKCS1v15"},
			"golang.org/x/crypto/curve25519": {"ScalarMult"},	//ScalarMult弃用
			"golang.org/x/crypto/pkcs12": {"Decode", "ToPEM"},	//pkcs12弃用
			"golang.org/x/crypto/poly1305": {"Sum", "Verify"},	//poly1305弃用
			"golang.org/x/crypto/chacha20": {"HChaCha20"},

			"crypto/des": {"NewTripleDESCipher"},
			"crypto/sha256": {"New224", "Sum224"},
			"crypto/sha512": {"New512_224", "Sum512_224"},
			"golang.org/x/crypto/sha3": {"New224", "Sum224"},
	} , map[string]string{
			"golang.org/x/crypto/twofish": "2 - Twofish - CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
			"crypto/rsa": "2 - RSASSA-PKCS1-v1_5 is deprecated, RSASSA-PSS is recommended， that is, \"SignPSS\"",
			"golang.org/x/crypto/curve25519": "2 - curve25519弃用ScalarMult方法",	//ScalarMult弃用
			"golang.org/x/crypto/pkcs12": "2 - 弃用pkcs12",
			"golang.org/x/crypto/poly1305": "2 - 弃用poly1305，建议使用chacha20poly1305",
			"golang.org/x/crypto/chacha20": "2 - chacha20 - Do not use chacha20 encryption, chacha20poly1305 is recommended.",

			"crypto/des": "3 - 3DES",
			"crypto/sha256": "3 - SHA-224 - NIST 800-57 : In 2031 and beyond, SHA-224 shall not be used for applying cryptographic protection.",
			"crypto/sha512": "3 - SHA-512/224 - NIST 800-57 : In 2031 and beyond, SHA-512/224 shall not be used for applying cryptographic protection.",
			"golang.org/x/crypto/sha3": "3 - SHA3-224 - NIST 800-57 : In 2031 and beyond, SHA3-224 shall not be used for applying cryptographic protection.",

		}
}

func cryptoFuncs4() (map[string][]string, map[string]string) {
	return map[string][]string{
			//"crypto/aes": {"NewCipher"},
			"golang.org/x/crypto/chacha20poly1305": {"New", "NewX"},
			"golang.org/x/crypto/salsa20": {"XORKeyStream"},
			"crypto/ed25519": {"GenerateKey"},
			"golang.org/x/crypto/ed25519": {"GenerateKey"},
			"golang.org/x/crypto/curve25519": {"ScalarBaseMult", "X25519"},	//ScalarMult弃用
			"crypto/sha256": {"New", "Sum256"},
			"crypto/sha512": {"New512_256", "Sum512_256"},
			"golang.org/x/crypto/sha3": {"New256", "Sum256", "NewLegacyKeccak256", "ShakeSum128", "NewCShake128", "NewShake128"},
			"golang.org/x/crypto/blake2s": {"New128", "New256", "Sum256"},
			"golang.org/x/crypto/bcrypt": {"CompareHashAndPassword", "Cost", "GenerateFromPassword"},	//
			//"crypto/hmac": {"New"},
		} , map[string]string{
			//"crypto/aes":"4 - aes",
			"golang.org/x/crypto/chacha20poly1305": "4 - chacha20poly1305",
			"golang.org/x/crypto/salsa20": "4 - salsa20",
			"crypto/ed25519": "4 - ed25519",
			"golang.org/x/crypto/ed25519": "4 - 【ed25519】",
			"golang.org/x/crypto/curve25519": "4 - curve25519",
			"crypto/sha256": "4 - SHA-256",
			"crypto/sha512": "4 - SHA-512/256",
			"golang.org/x/crypto/sha3": "4 - SHA3-256、SHAKE-128",
			"golang.org/x/crypto/blake2s": "4 - blake2s",
			"golang.org/x/crypto/bcrypt": "bcrypt",
			//"crypto/hmac": "hmac",
		}
}

func highcryptoFuncs5() (map[string][]string, map[string]string) {
	return map[string][]string{
			"crypto/sha512": {"New384", "Sum384", "New", "Sum512"},
			"golang.org/x/crypto/sha3": {"New384", "Sum384", "New512", "Sum512", "NewLegacyKeccak512", "ShakeSum256", "NewCShake256", "NewShake256"},
			"golang.org/x/crypto/blake2b": {"New", "New256", "New384", "New512", "Sum256", "Sum384", "Sum512"},
		} , map[string]string{
			"crypto/sha512": "5 - SHA-384、SHA-512",
			"golang.org/x/crypto/sha3": "5 - SHA3-384、SHA3-512、SHAKE-256",
			"golang.org/x/crypto/blake2b": "5 - blake2b",
		}
}


// weakcryptoRun runs the weakcrypto analyzer
func weakcryptoRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Creates call graph of function calls
	cg := make(util.CallGraph)

	// Fills in call graph
	if !run.CGFlat {	//wening
		// Builds SSA model of Go code
		ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs	//这里调用了一下传进来的所有自定义函数名

		//fmt.Println("***************")
		for _, fn := range ssa_functions { //所以这一步是在构造调用图对吗 —— 对
			cg.AnalyzeFunctionO(fn)
		}
		//fmt.Println("**",cg,"**")
		run.CG = cg
	} else {
		cg = run.CG //wening
	}

	//初始化 不能清空
	//util.Cwelist = make(map[string]bool)

	// Grabs vulnerable functions to scan for
	weak01, wOutput := weakcryptoFuncs01()
	//填充cwe列表
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
			for _, vulnFunc := range cg[current_function] {	//通过头文件.函数名，查找调用图中对应的 CGRelation{*ssa.Call，*ssa.Function}

				message := "Danger: Prohibited to use "
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				results = append(results, util.MakeFinding(message, targetFunc, nil, wOutput[pkg]))
			}
		}
	}

	//***********************************************************************************************************************

	// Grabs vulnerable functions to scan for
	weakcryptofuncs23, wOutput23 := weakcryptoFuncs23()
	//填充cwe列表
	for _, output := range wOutput23{
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}

	// Iterate over every specified vulnerable package
	for pkg, funcs := range weakcryptofuncs23 {
		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {
			// Construct full name of function
			current_function := pkg + "." + fn
			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] { //通过头文件.函数名，查找调用图中对应的 CGRelation{*ssa.Call，*ssa.Function}

				message := "Danger: Not recommended "
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				results = append(results, util.MakeFinding(message, targetFunc, nil, wOutput23[pkg]))
			}
		}
	}

	//***********************************************************************************************************************

	// Grabs vulnerable functions to scan for
	cryptofuncs4, wOutput4 := cryptoFuncs4()
	//填充cwe列表
	/*for _, output := range wOutput4 {
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}*/

	// Iterate over every specified vulnerable package
	for pkg, funcs := range cryptofuncs4 {
		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {
			// Construct full name of function
			current_function := pkg + "." + fn
			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] { //通过头文件.函数名，查找调用图中对应的 CGRelation{*ssa.Call，*ssa.Function}

				s := wOutput4[pkg]
				if(strings.Contains(current_function,"blake2s") || !strings.Contains(pkg,"sha3")) {
					s = s
				} else if(strings.Contains(fn,"128")) {
					s += "----128"
				} else if(strings.Contains(fn,"256")) {
					s += "----256"
				}
				util.Cwelist[s] = true
				message := "Best Practices"
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				results = append(results, util.MakeFinding(message, targetFunc, nil, s))
			}
		}
	}

	//***********************************************************************************************************************

	// Grabs vulnerable functions to scan for
	highcryptofuncs5, wOutput5 := highcryptoFuncs5()
	//填充cwe列表
	/*for _, output := range wOutput5 {
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}*/

	// Iterate over every specified vulnerable package
	for pkg, funcs := range highcryptofuncs5 {
		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {
			// Construct full name of function
			current_function := pkg + "." + fn
			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] { //通过头文件.函数名，查找调用图中对应的 CGRelation{*ssa.Call，*ssa.Function}

				s := wOutput5[pkg]
				if(strings.Contains(current_function,"blake2b")) {
					s = s
				} else if(strings.Contains(fn,"384")) {
					s += "----384"
				} else if(strings.Contains(fn,"256")) {
					s += "----256"
				} else if(strings.Contains(fn,"512") || strings.Contains(fn,"New")) {
					s += "----512"
				}
				message := "Best Practices"
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				util.Cwelist[s] = true
				results = append(results, util.MakeFinding(message, targetFunc, nil, s))
			}
		}
	}
	return results, nil
}