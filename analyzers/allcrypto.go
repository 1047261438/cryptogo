/*wening —— weakcrypto*/
package analyzers

import (
	"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"
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
func allcryptoFuncs() (map[string][]string, map[string]string) {	//写map是因为它不按顺序输出，只能查找键。。。
	return map[string][]string{	//函数名
			"crypto/des": {"NewCipher", "NewTripleDESCipher"},	//还需要考虑一下2tdea和3tdea怎么区分
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

			"crypto/cipher": {"NewCBCEncrypter", "NewCFBEncrypter","NewOFB", "NewCTR", "NewGCM"},	//建议：CBC的lucky13攻击，考虑一下吧；CFB的iv要不可预测；OFB不允许重用iv；CTR要检查计数器块	//CBC的iv要不可预测已经实现了
			"golang.org/x/crypto": {"NewCipher"},
			"crypto/rsa": {"GenerateKey", "SignPKCS1v15", "EncryptPKCS1v15", "EncryptOAEP", "SignPSS"},	//不推荐RSAES-PKCS1-v1_5、RSASSA-PKCS1-v1_5;推荐RSAES-OAEP、RSASSA-PSS;
			"crypto/elliptic": {"P224", "P256", "P384", "P512"},	//这里要斟酌实现形式，是使用就有问题，还是在ecdsaa里面使用有问题
			"golang.org/x/crypto/bn256": {"G1", "G2", "GT"},	//弃用
			"golang.org/x/crypto/argon2": {"Key", "IDKey"},	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/bcrypt": {"GenerateFromPassword", "newFromHash", "bcrypt"},	//密钥派生函数
			"golang.org/x/crypto/hkdf": {"Extract", "New"},	//密钥派生函数，第3个参数是盐值
			"golang.org/x/crypto/pbkdf2": {"Key"},	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/scrypt": {"Key"},	//密钥派生函数，第2个参数是盐值

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
			"golang.org/x/crypto/curve25519": {"ScalarBaseMult", "ScalarMult", "X25519"},	//ScalarMult弃用
			"golang.org/x/crypto/pkcs12": {"Decode", "ToPEM"},	//pkcs12弃用
			"golang.org/x/crypto/poly1305": {"Sum", "Verify"},	//poly1305弃用
			"golang.org/x/crypto/salsa20": {"XORKeyStream"},
			"golang.org/x/crypto/xts": {"NewCipher"},
			"golang.org/x/crypto/internal/poly1305": {"Sum", "Verify"},

		} , map[string]string{	//警告信息
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
			"crypto/sha256": "224/256",
			"crypto/sha512": "384/512_224/512_256/512",
			"golang.org/x/crypto/sha3": "NIST 800-57 : In 2031 and beyond, SHA3-224 shall not be used for applying cryptographic protection.",
			"crypto/ripemd160": "Mendel et al. On the Collision Resistance of RIPEMD-160 *",

			"crypto/cipher": "CBC/cfb/ofb/CTR",
			"golang.org/x/crypto": "xts",
			"crypto/rsa": "CWE-rsa-padding5",
			"crypto/elliptic":"P-224/P-256/P-384",
			"golang.org/x/crypto/bn256":"This package is frozen, and not implemented in constant time.",
			"golang.org/x/crypto/argon2": "argon2",	//密钥派生函数
			"golang.org/x/crypto/bcrypt": "bcrypt",	//密钥派生函数
			"golang.org/x/crypto/hkdf": "hkdf",	//密钥派生函数
			"golang.org/x/crypto/pbkdf2": "pbkdf2",	//密钥派生函数
			"golang.org/x/crypto/scrypt": "scrypt",	//密钥派生函数
			
			"crypto/aes": "aes",
			"crypto/dsa": "dsa",
			"crypto/ecdsa": "ecdsa",
			"crypto/hmac": "hmac",

			"crypto/ed25519": "ed25519",
			"golang.org/x/crypto/ed25519": "【ed25519】",
			"golang.org/x/crypto/blake2b": "blake2b",
			"golang.org/x/crypto/blake2s": "blake2s",
			"golang.org/x/crypto/chacha20": "chacha20",
			"golang.org/x/crypto/chacha20poly1305": "chacha20poly1305",
			"golang.org/x/crypto/curve25519": "ScalarMult弃用",	//ScalarMult弃用
			"golang.org/x/crypto/pkcs12": "弃用",
			"golang.org/x/crypto/poly1305": "弃用",
			"golang.org/x/crypto/salsa20": "salsa20",
			"golang.org/x/crypto/xts": "xts",
			"golang.org/x/crypto/internal/poly1305": "【poly1305】",
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
	all, wOutput := allcryptoFuncs()
	//填充cwe列表
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
			for _, vulnFunc := range cg[current_function] {	//通过头文件.函数名，查找调用图中对应的 CGRelation{*ssa.Call，*ssa.Function}

				message := "all use "
				targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				results = append(results, util.MakeFinding(message, targetFunc, nil, wOutput[pkg]))
			}
		}
	}
	return results, nil
}