/*wening —— random*/
package analyzers

import (
	"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"
"fmt"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// AESKeyLenAnalyzer
var RandomAnalyzer = &analysis.Analyzer{
	Name:     "random",
	Doc:      "random generation is not correct",
	Run:      randomRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// sinkRandomFuncs() returns a map of functions that CBC
func sinkRandomFuncs() (map[string][]int, map[string][]string, map[string]string) {
	return  map[string][]int{	//参数位置
			"crypto/cipher": {1,1,1,1},	//第二个参数
			"crypto/rsa": {1, 0, 0, 0},
			"crypto/dsa": {1, 1, 0},
			"crypto/ecdsa": {0, 0, 1},
			"golang.org/x/crypto/argon2": {1, 1},	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/hkdf": {2},	//密钥派生函数，第3个参数是盐值
			"golang.org/x/crypto/pbkdf2": {1},	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/scrypt": {1},	//密钥派生函数，第2个参数是盐值
			"crypto/aes": {0},

			//"crypto/dsa": {1, 1, 0},
			//"crypto/rsa": {1,0,0,0,0},

		}, map[string][]string{
			"crypto/cipher": {"NewCBCEncrypter", "NewCFBEncrypter", "NewCTR", "NewOFB"},
			"crypto/rsa": {"EncryptOAEP", "SignPSS", "GenerateKey", "GenerateMultiPrimeKey"},
			"crypto/dsa": {"GenerateKey", "GenerateParameters", "Sign"},
			"crypto/ecdsa": {"Sign", "SignASN1", "GenerateKey"},
			"golang.org/x/crypto/argon2": {"IDKey", "Key"},	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/hkdf": {"New"},	//密钥派生函数，第3个参数是盐值
			"golang.org/x/crypto/pbkdf2": {"Key"},	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/scrypt": {"Key"},	//密钥派生函数，第2个参数是盐值
			"crypto/aes": {"NewCipher"},

			//"golang.org/x/crypto/bcrypt": {"GenerateFromPassword", "newFromHash", "bcrypt"},
			//"crypto/dsa": {"GenerateParameters", "GenerateKey", "Sign"},
			//"crypto/rsa": {"EncryptOAEP", "SignPSS", "GenerateKey", "GenerateMultiPrimeKey", "Sign"},//{"SignPKCS1v15"0, "EncryptPKCS1v15"0, "DecryptPKCS1v15"0}与weakcrypto.go做取舍
		} , map[string]string{	//警告信息
			//"crypto/cipher": "CWE-329: Generation of Predictable IV with CBC Mode",
			"crypto/cipher": "IV",
			"crypto/rsa": "rsa要配置prng",
			"crypto/dsa": "dsa要配置prng",
			"crypto/ecdsa": "ecdsa要配置prng",
			"golang.org/x/crypto/argon2": "argon2-salt要随机",	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/hkdf": "hkdf-salt要随机",	//密钥派生函数，第3个参数是盐值
			"golang.org/x/crypto/pbkdf2": "pbkdf2-salt要随机",	//密钥派生函数，第2个参数是盐值
			"golang.org/x/crypto/scrypt": "scrypt-salt要随机",	//密钥派生函数，第2个参数是盐值
			"crypto/aes": "AES密钥要随机",

			//"golang.org/x/crypto/bcrypt": "",
			//"crypto/dsa":"dsa is not randomly",
			//"crypto/rsa": "rsa is not randomly",
		}
}
// sourceRandomFuncs() returns a map of functions that CBC
func sourceRandomFuncs() map[string][]string {
	return map[string][]string{
		"math/rand": {"Read", "Intn", "Int", "Int63", "Int31", "Int31n", "Int63n"},
		"encoding/hex": {"DecodeString"},
	}
}
// filtersRandomFuncs() returns a map of functions that CBC
func filtersRandomFuncs() map[string][]string {
	return map[string][]string{
		"crypto/rand": {"Read", "Reader"},	//参数过滤在*ssa.Global
		"io": {"ReadFull"},	//函数过滤在*ssa.Call

		"crypto/md5": {"New", "Sum"},
		"crypto/sha1": {"New", "Sum"},
		"crypto/sha256": {"New224", "Sum224", "New", "Sum256"},
		"crypto/sha512": {"New", "Sum512", "New384", "Sum384", "New512_224", "Sum512_224", "New512_256", "Sum512_256"},
		"golang.org/x/crypto/sha3": {"New224", "Sum224", "New256", "New384", "New512",  "Sum256", "Sum384", "Sum512",
			"NewLegacyKeccak256", "NewLegacyKeccak512", "ShakeSum128", "ShakeSum256"},
		"golang.org/x/crypto/argon2": {"IDKey", "Key"},	//密钥派生函数，第2个参数是盐值
		"golang.org/x/crypto/hkdf": {"New"},	//密钥派生函数，第3个参数是盐值
		"golang.org/x/crypto/pbkdf2": {"Key"},	//密钥派生函数，第2个参数是盐值
		"golang.org/x/crypto/scrypt": {"Key"},	//密钥派生函数，第2个参数是盐值
	}
}

func randomRun(pass *analysis.Pass) (interface{}, error) {

	results := []util.Finding{}

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	// Fills in call graph
	if !run.CGFlat {	//wening
		// Builds SSA model of Go code
		ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs	//这里调用了一下传进来的所有自定义函数名

		//fmt.Println("***************")
		for _, fn := range ssa_functions { //所以这一步是在构造调用图对吗 —— 对
			call_graph.AnalyzeFunctionO(fn)
		}
		//fmt.Println("**",cg,"**")
		run.CG = call_graph
	} else {
		call_graph = run.CG //wening
	}

	//暂存数据，测试
	VulnGlobalFuncs_temp := util.VulnGlobalFuncs
	util.VulnGlobalFuncs = make(map[string][]string)
	util.VulnGlobalFuncs = sourceRandomFuncs()

	//设置过滤数据
	util.FiltersGlobalFuncs = make(map[string][]string)
	util.FiltersGlobalFuncs = filtersRandomFuncs()

	// Grabs vulnerable functions to scan for
	vuln_random_parameter, vuln_random_funcs, wOutput := sinkRandomFuncs()
	/*//填充cwe列表
	for _, output := range wOutput{
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}*/

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_random_funcs {
		parameter := vuln_random_parameter[pkg]	//记录哪个函数检查哪个参数

		// Iterate over every specified vulnerable function per package
		for i, fn := range funcs {
			parameterI := parameter[i]	//第i个参数

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {
				// vulnFunc.Fn.String() 记录了上面 sink 所属的调用方法名

				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				var taintSource []util.TaintedCode
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[parameterI], call_graph) {	//wening iv随机性不强，匹配到不够优秀的随机数生成器
					/*if current_function == "crypto/hmac.New" {
						output = "Using HMAC with broken hash function"
						message = "Danger: Don't broken hash function"
					}*/
					message := "Danger: Don't generate or use a predictable initialization Vector (IV) with Cipher Block Chaining (CBC) Mode"
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, wOutput[pkg]))
				} else if util.CallFlat {	//wening iv不随机，没有匹配到随机性不强的生成器，也没有过滤正确的随机数生成器，即未进行随机化，或者自实现了随机性，这也不安全
					//添加了对HMAC参数的判断，因为直接匹配里面的hash函数匹配不到，需要匹配参数
					output := ""
					message := ""
					/*if vulnFunc.Instr.Call.Args[parameterI].String() == "crypto/md5.New" {
						output = "Using HMAC with broken hash function - hmac_md5"
						message = "Danger: Don't broken hash function"
					} else if vulnFunc.Instr.Call.Args[parameterI].String() == "crypto/sha1.New" {
						output = "Using HMAC with broken hash function - hmac_sha1"
						message = "Danger: Don't broken hash function"
					} else if current_function == "crypto/hmac.New" {
						continue
					} else {*/
					s := pkg
					if(s=="crypto/cipher") {
						s = current_function
					}
					output = "Generation of Constant IV/key ----" + s
					message = "Danger: Don't use Constant IV"
					/*}*/
					if !util.Cwelist[output] {
						util.Cwelist[output] = true
					}
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, output))
				} else { fmt.Println("过滤")
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					fmt.Println(targetFunc,"\n",taintSource)
				}
			}
		}
	}
	//恢复数据，测试
	util.VulnGlobalFuncs = VulnGlobalFuncs_temp
	return results, nil
}
