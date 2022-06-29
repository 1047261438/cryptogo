/*wening —— functaint*//*这一部分未必用得上，这种粗判断有待商榷*/
package analyzers
import (
	//"fmt"
	"strings"
"github.com/praetorian-inc/gokart/run"	//wening
"github.com/praetorian-inc/gokart/util"

"golang.org/x/tools/go/analysis"
"golang.org/x/tools/go/analysis/passes/buildssa"
)

// AESKeyLenAnalyzer
var FuncTaintAnalyzer = &analysis.Analyzer{
	Name:     "function taint",
	Doc:      "misuse crypto function",
	Run:      funcRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// sinkFuncs() returns a map of functions that CBC、CTR
func sinkFuncs() (map[string][]int, map[string][]string) {
	return map[string][]int{	//参数位置
			//"crypto/cipher": {0,0},	//第一个参数

			"crypto/ecdsa": {0},	//第一个参数
			"crypto/hmac": {0},
			"crypto/des": {0},
			//"golang.org/x/crypto/hkdf": {1},
		}, map[string][]string{
			//"crypto/cipher": {"NewCBCEncrypter","NewCTR"},

			"crypto/ecdsa": {"GenerateKey"},
			"crypto/hmac": {"New"},
			"crypto/des": {"NewTripleDESCipher"},
			//"golang.org/x/crypto/hkdf": {"New"},
		}
}
// sourceFuncs() returns a map of functions that CBC
func sourceFuncs() map[string][]string {
	return map[string][]string{
		//"crypto/aes": {"NewCipher"},	//想办法追溯这唯一的参数key，试图判断key的长度，16byte就可以认定是128位的（试图匹配[:16]也行）
		"crypto/elliptic": {"P224", "P256", "P384", "P521"},
		"crypto/md5": {"New", "Sum"},
		"crypto/sha1": {"New", "Sum"},
		"crypto/sha256": {"New224", "Sum224", "New", "Sum256"},
		"crypto/sha512": {"New", "Sum512", "New384", "Sum384", "New512_224", "Sum512_224", "New512_256", "Sum512_256"},
		"golang.org/x/crypto/sha3": {"New224", "Sum224", "New256", "New384", "New512",  "Sum256", "Sum384", "Sum512",
			"NewLegacyKeccak256", "NewLegacyKeccak512", "ShakeSum128", "ShakeSum256"},
		//"shadowsocks": {},
	}
}

//警报信息输出——最佳实践这个说法是不是可以最后挑出来说，不然太多了
func functaint_out(t util.TaintedCode, function string) (string, string) {
	message := "NULL"
	output := "NULL"
	//fmt.Println("t.SourceCode:",t.SourceFilename)
	/*if function == "NewCBCEncrypter" {
		message = "Danger: Don't use the operation mode \" CBC \" if AES is used."
		output = "2 - AES_CBC"
	} else if function == "NewCTR"{
		message = "Danger: Don't use the operation mode \" CTR \" if AES is used."
		output = "2 - AES_CTR"
	} else*/ if strings.Contains(t.SourceCode, "P224") {
		message = "Danger: Don't use the elliptic \" P224 \" if ECDSA is used "
		output = "3 - ECDSA_P224"
	} else if strings.Contains(t.SourceCode, "P256") {
		message = "Best Practice: ECDSA with the elliptic \" P256 \""
		output = "4 - ECDSA_P256"
	} else if strings.Contains(t.SourceCode, "P384") {
		message = "High: High strength may affect performance, best practice is \" ECDSA_P256 \"."
		output = "5 - ECDSA_P384"
	} else if strings.Contains(t.SourceCode, "P521") {
		message = "High: High strength may affect performance, best practice is \" ECDSA_P256 \"."
		output = "5 - ECDSA_P521"
	} else if strings.Contains(t.SourceFilename, "md5") {
		message = "Danger: Don't use HMAC_MD5, best practice is \" HMAC-SHA256 \"."
		output = "2 - HMAC_MD5"
	} else if strings.Contains(t.SourceFilename, "sha1") {
		message = "Best Practice: HMAC_SHA1 can be uesd, and best practice is \" HMAC-SHA256 \"."
		output = "4 - HMAC_SHA1"
	} else if strings.Contains(t.SourceFilename, "sha256") {
		message = "Best Practice"
		output = "4 - HMAC_SHA256"
	} else if strings.Contains(t.SourceFilename, "sha512") {
		message = "High: High strength may affect performance, best practice is \" HMAC-SHA256 \"."
		output = "5 - HMAC_SHA512"
	} else if strings.Contains(t.SourceFilename, "sha3") {
		message = "High: High strength may affect performance, best practice is \" HMAC-SHA256 \"."
		output = "5 - HMAC_SHA3"
	}
	//fmt.Println(output)
	util.Cwelist[output] = true	//填充cwe列表
	return message,output
}

func funcRun(pass *analysis.Pass) (interface{}, error) {

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
	util.VulnGlobalFuncs = sourceFuncs()

	// Grabs vulnerable functions to scan for
	vuln_taint_parameter, vuln_taint_funcs := sinkFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_taint_funcs {
		parameter := vuln_taint_parameter[pkg]	//记录哪个函数检查哪个参数

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
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[parameterI], call_graph) {
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					message,output := functaint_out(taintSource[0],fn)
					//fmt.Println("fn:", fn)
					//fmt.Println("targetFunc:",strings.Contains(targetFunc.SourceCode, "P224"))
					//fmt.Println(output)
					util.Cwelist[output] = true	//填充cwe列表
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, output))
				}
			}
		}
	}

	//恢复数据，测试
	util.VulnGlobalFuncs = VulnGlobalFuncs_temp
	return results, nil
}
