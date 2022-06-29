/*wening —— lowlength*/
package analyzers

import (
	"fmt"
	"go/constant"
	"go/token"
	"strings"
	"strconv"

	"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"

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

var RECOMMENDED_KEYLEN []int64	//暂存
var RECOMMENDED_KEYLEN_ string	//最终暂存

// vulnerableFuncsH() returns a map of functions that generate keys
//vuln_keylen, vuln_parameter, vuln_funcs, vuln_Output
func vulnerableFuncsH() (map[string][]int64, map[string][]int, map[string][]string, map[string]string){
	return map[string][]int64 {	//长度
			"crypto/rsa": {512,1024,2048,4096,7680,15360},	//512
			"crypto/dsa": {1,2,3,4},	//dsa.L1024N160 = iota
			"crypto/des": {16,32},	//nil
			//"crypto/tls": 0x0005,
			//"crypto/ecdsa": elliptic.P160-223(),
		}, map[string][]int{	//参数位置
			"crypto/rsa": {1,2},	//第二\三个参数
			"crypto/dsa": {2},	//第三个参数
			"crypto/des": {0},	//第1个参数
			//"crypto/tls": {0},
			//"crypto/ecdsa": {0},	//第一个参数
		}, map[string][]string{	//函数名
			"crypto/rsa": {"GenerateKey", "GenerateMultiPrimeKey"},
			"crypto/dsa": {"GenerateParameters"},
			"crypto/des": {"NewTripleDESCipher"},
			//"crypto/tls": {"CipherSuiteName"},
			//"crypto/ecdsa": {"GenerateKey"},
		} , map[string]string{	//警告信息
			"crypto/rsa": "rsa",
			"crypto/dsa": "dsa",
			"crypto/des": "3des",
			//CWE-326: Inadequate Encryption Strength
			//"crypto/tls": "CipherSuiteName",
			//"crypto/ecdsa": "CWE-326: Inadequate Encryption Strength - ecdsa",
		}
}

// vulnerableFuncsM() returns a map of functions that generate keys
//还没实现
func vulnerableFuncsM() (map[string]int64, map[string][]int, map[string][]string, map[string]string){
	return map[string]int64 {	//长度
			"crypto/rsa": 2048,
			"crypto/dsa": 2,	//dsa.L2048N224？
			//"crypto/ecdsa": elliptic.P224-255(),
		}, map[string][]int{	//参数位置
			"crypto/rsa": {1,2},	//第二\三个参数
			"crypto/dsa": {2},	//第三个参数
			//"crypto/ecdsa": {0},	//第一个参数
		}, map[string][]string{	//函数名
			"crypto/rsa": {"GenerateKey", "GenerateMultiPrimeKey"},
			"crypto/dsa": {"GenerateParameters"},
			//"crypto/ecdsa": {"GenerateKey"},
			//"crypto/des": {"NewTripleDESCipher"},	//还需要考虑一下des和3des怎么区分
		} , map[string]string{	//警告信息
			"crypto/rsa": "CWE-326: Inadequate Encryption Strength - rsa",
			"crypto/dsa": "CWE-326: Inadequate Encryption Strength - dsa",
			//"crypto/ecdsa": "CWE-326: Inadequate Encryption Strength - ecdsa",
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
	//fmt.Println(pass)
	//fmt.Println("______",keylen,"__________")
	//暂不知其他功能，目前仅用到了 1、4
	switch keylen := keylen.(type) {
	case *ssa.Const:		//该参数为数值（无论别名多少次，只要这里的类型是数值即可检测）
		//fmt.Println("1 - ",unsafe)
		real_len := keylen.Int64()
		//fmt.Println("长度：",real_len)
		for _, keyl := range RECOMMENDED_KEYLEN {
			//fmt.Print("检查：",keyl,"--")
			if real_len <= keyl {
				RECOMMENDED_KEYLEN_ = strconv.FormatInt(real_len,10)
				unsafe = true
				//fmt.Println("1 - ",unsafe)
			}
		}
		//fmt.Println()
	case *ssa.Phi:
		//fmt.Println("2 - ",unsafe)
		for _, edge := range keylen.Edges {
			if keylen != edge {
				unsafe = unsafe || keylen_check(pass, edge, cg)
			}
		}
	case *ssa.BinOp:
		//fmt.Println("3 - ",unsafe)
		if val, ok := EvalConst(keylen, cg); ok {
			unsafe = keylen_check(pass, val, cg)
		}
	case *ssa.Call:		//该参数为函数体（即，需要调用获取），可多次迭代
		//fmt.Println("4 - ",unsafe)
		callFunc, ok := (keylen.Call.Value).(*ssa.Function)
		fmt.Println("有函数吗！",callFunc)
		if ok {
			globalPkgNamePart := callFunc.Pkg.Pkg.Name()
			if(globalPkgNamePart == "des") {
				util.DESFlat =true
				fmt.Println("************", globalPkgNamePart)
			}
		}
		if dest := keylen.Common().StaticCallee(); dest != nil {
			returns := util.ReturnValues(dest)
			for _, retval := range returns {
				unsafe = unsafe || keylen_check(pass, retval[0], cg)
			}
			/*for _, retval := range returns {
				fmt.Println(retval[0].String())	//调用的函数
				if retval[0].String() == "b()" {	//从 sink 找到 source 截断，只能找到不带参的
					unsafe = true
				} else {
					unsafe = unsafe || keylen_check(pass, retval[0], cg)
				}
			}*/
		}
	case *ssa.Parameter:
		//fmt.Println("5 - ",unsafe)
		var values []*ssa.Value
		values = cg.ResolveParam(keylen)
		fmt.Println(keylen)
		if len(values) > 0 {
			unsafe = unsafe || keylen_check(pass, *values[0], cg)
		}
	case *ssa.Convert:	//
		//fmt.Println("6 - ",unsafe)
		if(util.DESFlat == true) {
			if(strings.Count(keylen.X.Name(),"")-10 < 32) {
				fmt.Println("EDE2 ", keylen.X.Name(), " : ", strings.Count(keylen.X.Name(),""))	//多10个字符
			} else {
				fmt.Println("EDE3 ", keylen.X.Name(), " : ", strings.Count(keylen.X.Name(),""))	//多10个字符
			}
			util.DESFlat = false
			unsafe = true
		}
	case *ssa.Alloc:
		//fmt.Println("7 - ",unsafe)
		if(util.DESFlat == true) {
			len,_ := strconv.Atoi(keylen.String()[5:7])	//小于10的内容截取带 ] ，无法转数字，得到0，符合<=16的要求
			if(len < 32) {
				fmt.Println("[EDE2] instr: ", keylen.String())
			} else {
				fmt.Println("[EDE3] instr: ", keylen.String())
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

	//清空内存 不能清空
	//util.Cwelist = make(map[string]bool)
	// Grabs vulnerable functions to scan for
	vuln_keylen, vuln_parameter, vuln_funcs, vuln_Output := vulnerableFuncsH()
	//填充cwe列表
	for _, output := range vuln_Output{
		if !util.Cwelist[output] {
			util.Cwelist[output] = true
		}
	}

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_funcs {
		parameter := vuln_parameter[pkg]	//记录哪个函数检查哪个参数
		RECOMMENDED_KEYLEN = vuln_keylen[pkg]	//记录哪个函数检查哪个长度

		// Iterate over every specified vulnerable function per package
		for i, fn := range funcs {
			parameterI := parameter[i]	//第i个参数

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrenceis of vulnerable function in call graph
			for _, vulnFunc := range cg[current_function] {
				//targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
				//fmt.Println(targetFunc)
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
