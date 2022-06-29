package analyzers
import (
	"strings"
	"github.com/1047261438/cryptogo/run"
	"github.com/1047261438/cryptogo/util"

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
	return map[string][]int{
			"crypto/ecdsa": {0},
			"crypto/hmac": {0},
			"crypto/des": {0},
		}, map[string][]string{
			"crypto/ecdsa": {"GenerateKey"},
			"crypto/hmac": {"New"},
			"crypto/des": {"NewTripleDESCipher"},
		}
}
// sourceFuncs() returns a map of functions that CBC
func sourceFuncs() map[string][]string {
	return map[string][]string{
		"crypto/elliptic": {"P224", "P256", "P384", "P521"},
		"crypto/md5": {"New", "Sum"},
		"crypto/sha1": {"New", "Sum"},
		"crypto/sha256": {"New224", "Sum224"},	//detect SHA256, Please add "New", "Sum256"
		//"crypto/sha512": {"New", "Sum512", "New384", "Sum384", "New512_224", "Sum512_224", "New512_256", "Sum512_256"},	//detect SHA512, Please add this
		"golang.org/x/crypto/sha3": {"New224", "Sum224"},	//detect SHA3-256、SHA3-384、SHA3-512, Please add "New256", "New384", "New512",  "Sum256", "Sum384", "Sum512", "NewLegacyKeccak256", "NewLegacyKeccak512", "ShakeSum128", "ShakeSum256"
	}
}

func functaint_out(t util.TaintedCode, function string) (string, string) {
	message := "NULL"
	output := "NULL"
	if strings.Contains(t.SourceCode, "P224") {
		message = "Danger: Don't use the elliptic \" P224 \" if ECDSA is used "
		output = "ECDSA_P224 - Acceptable but not recommended cryptographic algorithms."
	} else if strings.Contains(t.SourceCode, "P256") {
		message = "Best Practice: ECDSA with the elliptic \" P256 \""
		output = "ECDSA_P256 - Recommended."
	} else if strings.Contains(t.SourceCode, "P384") {
		message = "High: High strength may affect performance, best practice is \" ECDSA_P256 \"."
		output = "ECDSA_P384 - Recommended."
	} else if strings.Contains(t.SourceCode, "P521") {
		message = "High: High strength may affect performance, best practice is \" ECDSA_P256 \"."
		output = "ECDSA_P521 - Recommended."
	} else if strings.Contains(t.SourceFilename, "md5") {
		message = "Danger: Don't use HMAC_MD5, best practice is \" HMAC-SHA256 \"."
		output = "HMAC_MD5 - Acceptable but not recommended cryptographic algorithms."
	} else if strings.Contains(t.SourceFilename, "sha1") {
		message = "Best Practice: HMAC_SHA1 can be uesd, and best practice is \" HMAC-SHA256 \"."
		output = "HMAC_SHA1 - Recommended."
	} else if strings.Contains(t.SourceFilename, "sha256") {
		message = "Best Practice"
		output = "HMAC_SHA256 - Recommended."
	} else if strings.Contains(t.SourceFilename, "sha512") {
		message = "High: High strength may affect performance, best practice is \" HMAC-SHA256 \"."
		output = "HMAC_SHA512 - Recommended."
	} else if strings.Contains(t.SourceFilename, "sha3") {
		message = "High: High strength may affect performance, best practice is \" HMAC-SHA256 \"."
		output = "HMAC_SHA3 - Recommended."
	}
	util.Cwelist[output] = true
	return message,output
}

func funcRun(pass *analysis.Pass) (interface{}, error) {

	results := []util.Finding{}

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	// Fills in call graph
	if !run.CGFlat {
		// Builds SSA model of Go code
		ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs
		for _, fn := range ssa_functions {
			call_graph.AnalyzeFunctionO(fn)
		}
		run.CG = call_graph
	} else {
		call_graph = run.CG
	}

	VulnGlobalFuncs_temp := util.VulnGlobalFuncs
	util.VulnGlobalFuncs = make(map[string][]string)
	util.VulnGlobalFuncs = sourceFuncs()

	// Grabs vulnerable functions to scan for
	vuln_taint_parameter, vuln_taint_funcs := sinkFuncs()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_taint_funcs {
		parameter := vuln_taint_parameter[pkg]

		// Iterate over every specified vulnerable function per package
		for i, fn := range funcs {
			parameterI := parameter[i]

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {

				taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				var taintSource []util.TaintedCode
				if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[parameterI], call_graph) {
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					taintSource = taintAnalyzer.TaintSource
					message,output := functaint_out(taintSource[0],fn)
					util.Cwelist["NULL"] = false
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, output))
				}
			}
		}
	}

	util.VulnGlobalFuncs = VulnGlobalFuncs_temp
	return results, nil
}
