package analyzers

import (
	"fmt"
	"go/constant"
	"go/token"
	"strings"
	"strconv"

	"github.com/1047261438/cryptogo/run"
	"github.com/1047261438/cryptogo/util"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

//
var lowLengthAnalyzer = &analysis.Analyzer{
	Name:     "keylen",
	Doc:      "reports when crypto keys are too short",
	Run:      keylenRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

var RECOMMENDED_KEYLEN []int64
var RECOMMENDED_KEYLEN_ string

// vulnerableFuncsH() returns a map of functions that generate keys
func vulnerableFuncsH() (map[string][]int64, map[string][]int, map[string][]string, map[string]string){
	return map[string][]int64 {
			"crypto/rsa": {512,1024,2048},	// 3072,4096,7680,15360
			"crypto/dsa": {1,2,3},	//4 : L3072N256
			"crypto/des": {16,32},
		}, map[string][]int{
			"crypto/rsa": {1,2},
			"crypto/dsa": {2},
			"crypto/des": {0},
		}, map[string][]string{
			"crypto/rsa": {"GenerateKey", "GenerateMultiPrimeKey"},
			"crypto/dsa": {"GenerateParameters"},
			"crypto/des": {"NewTripleDESCipher"},
		} , map[string]string{
			"crypto/rsa": "RSA-512 and RSA-1024 is insecure, RSA-2048 is Acceptable but not recommended.",
			"crypto/dsa": "DSA-1024 is insecure, DSA-2048 is Acceptable but not recommended.",
			"crypto/des": "2TDEA is insecure.",
		}
}

// EvalConst attempts to take a value, and simplify it down to a single constant
// it returns a tuple of (the constant, whether or not it successfully simplified)
func EvalConst(expr ssa.Value, cg util.CallGraph) (*ssa.Const, bool) {

	switch expr := expr.(type) {

	case *ssa.Const:
		return expr, true
	case *ssa.BinOp:
		X, okX := EvalConst(expr.X, cg)
		Y, okY := EvalConst(expr.Y, cg)

		if okX && okY {
			return merge(X, Y, expr)
		}
	case *ssa.Call:
		if dest := expr.Common().StaticCallee(); dest != nil {
			rets := util.ReturnValues(dest)
			if len(rets) == 1 && len(rets[0]) == 1 {
				return EvalConst(rets[0][0], cg)
			}
		}
	case *ssa.Parameter:
		var values []*ssa.Value
		values = cg.ResolveParam(expr)
		return EvalConst(*values[0], cg)

	case *ssa.Phi:
		var res bool
		var val *ssa.Const
		val, res = EvalConst(expr.Edges[0], cg)

		for _, edge := range expr.Edges {
			var tmp *ssa.Const
			var tmp2 bool
			tmp, tmp2 = EvalConst(edge, cg)
			if tmp.Int64() < val.Int64() {
				val = tmp //val ends up being the shortest value that this phi node could be
			}
			res = res && tmp2 //res is whether or not the boolean expr could be evaluated
		}
		return val, res
	}

	return nil, false
}

// Merge merges two Consts to a BinOp
func merge(x, y *ssa.Const, op *ssa.BinOp) (*ssa.Const, bool) {
	switch op.Op {
	case token.ADD, token.SUB, token.MUL:
		return ssa.NewConst(constant.BinaryOp(x.Value, op.Op, y.Value), x.Type()), true
	case token.QUO:
		return ssa.NewConst(constant.BinaryOp(x.Value, token.QUO_ASSIGN, y.Value), x.Type()), true

	}
	return nil, false
}

// keylen_check recursively checks if a vulnerable function that relies on RSA is using a number of bits that is less than RECOMMENDED_KEYLEN
func keylen_check(pass *analysis.Pass, keylen ssa.Value, cg util.CallGraph) bool {
	unsafe := false
	switch keylen := keylen.(type) {
	case *ssa.Const:
		real_len := keylen.Int64()
		for _, keyl := range RECOMMENDED_KEYLEN {
			if real_len <= keyl {
				RECOMMENDED_KEYLEN_ = strconv.FormatInt(real_len,10)
				unsafe = true
			}
		}
	case *ssa.Phi:
		for _, edge := range keylen.Edges {
			if keylen != edge {
				unsafe = unsafe || keylen_check(pass, edge, cg)
			}
		}
	case *ssa.BinOp:
		if val, ok := EvalConst(keylen, cg); ok {
			unsafe = keylen_check(pass, val, cg)
		}
	case *ssa.Call:
		callFunc, ok := (keylen.Call.Value).(*ssa.Function)
		if ok {
			globalPkgNamePart := callFunc.Pkg.Pkg.Name()
			if(globalPkgNamePart == "DES") {
				util.DESFlat =true
				fmt.Println("************", globalPkgNamePart)
			}
		}
		if dest := keylen.Common().StaticCallee(); dest != nil {
			returns := util.ReturnValues(dest)
			for _, retval := range returns {
				unsafe = unsafe || keylen_check(pass, retval[0], cg)
			}
		}
	case *ssa.Parameter:
		var values []*ssa.Value
		values = cg.ResolveParam(keylen)
		//fmt.Println(keylen)
		if len(values) > 0 {
			unsafe = unsafe || keylen_check(pass, *values[0], cg)
		}
	case *ssa.Convert:
		if(util.DESFlat == true) {
			if(strings.Count(keylen.X.Name(),"")-10 < 32) {
				fmt.Println("2TDEA ", keylen.X.Name(), " : ", strings.Count(keylen.X.Name(),""))
			} else {
				fmt.Println("3TDEA", keylen.X.Name(), " : ", strings.Count(keylen.X.Name(),""))
			}
			util.DESFlat = false
			unsafe = true
		}
	case *ssa.Alloc:
		if(util.DESFlat == true) {
			len,_ := strconv.Atoi(keylen.String()[5:7])
			if(len < 32) {
				fmt.Println("[2TDEA] instr: ", keylen.String())
			} else {
				fmt.Println("[3TDEA] instr: ", keylen.String())
			}
			util.DESFlat = false
		}

	}
	return unsafe
}



// keylenRun runs the crypto keylength analyzer
func keylenRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Creates call graph of function calls
	cg := make(util.CallGraph)

	// Fills in call graph
	cg = run.CG //wening

	//util.Cwelist = make(map[string]bool)

	// Grabs vulnerable functions to scan for
	vuln_keylen, vuln_parameter, vuln_funcs, vuln_Output := vulnerableFuncsH()
	for _, output := range vuln_Output{
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_funcs {
		parameter := vuln_parameter[pkg]
		RECOMMENDED_KEYLEN = vuln_keylen[pkg]

		// Iterate over every specified vulnerable function per package
		for i, fn := range funcs {
			parameterI := parameter[i]

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrenceis of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] {
				if keylen_check(pass, vulnFunc.Instr.Call.Args[parameterI], cg) {
					message := fmt.Sprintf("Danger: key length is too short --"+RECOMMENDED_KEYLEN_)
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					out := vuln_Output[pkg]+"--"+RECOMMENDED_KEYLEN_
					util.Cwelist[out] = true
					results = append(results, util.MakeFinding(message, targetFunc, nil, out))
				}
			}
		}
	}

	return results, nil
}
