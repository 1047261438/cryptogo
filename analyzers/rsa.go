// Copyright 2021 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzers

import (
	"fmt"
	"go/constant"
	"go/token"

	"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// RSAKeyLenAnalyzer is used to resolve constant values used for RSA key generation in order to more accurately
// detect use of an insecure RSA key length constructed
// all variables are converted to SSA form and a call graph is constructed
// recursive analysis is then used to resolve variables used as a key length to a final constant value at the callsite
var RsaKeylenAnalyzer = &analysis.Analyzer{
	Name:     "rsa_keylen",
	Doc:      "reports when rsa keys are too short",
	Run:      rsaRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

const RECOMMENDED_KEYLEN_RSA = 2048
const RECOMMENDED_KEYLEN_ECB_BLOCK = 16

// vulnerableRsaFuncs() returns a map of functions that generate RSA keys
func vulnerableRsaFuncs() map[string][]string {
	return map[string][]string{
		"crypto/rsa": {"GenerateKey"},
	}
}
//wening未实现
func vulnerableECBFuncs() map[string][]string {		//间接调用的调用图有问题
	return map[string][]string{
		"crypto/cipher": {"Encrypt"},
	}
}

// rsaEvalConst attempts to take a value, and simplify it down to a single constant
// it returns a tuple of (the constant, whether or not it successfully simplified)
func rsaEvalConst(expr ssa.Value, cg util.CallGraph) (*ssa.Const, bool) {

	switch expr := expr.(type) {

	case *ssa.Const:
		return expr, true
	case *ssa.BinOp:
		X, okX := rsaEvalConst(expr.X, cg)
		Y, okY := rsaEvalConst(expr.Y, cg)

		if okX && okY {
			return rsa_merge(X, Y, expr)
		}
	case *ssa.Call:
		if dest := expr.Common().StaticCallee(); dest != nil {
			rets := util.ReturnValues(dest)
			if len(rets) == 1 && len(rets[0]) == 1 {
				return rsaEvalConst(rets[0][0], cg)
			}
		}
	case *ssa.Parameter:
		var values []*ssa.Value
		values = cg.ResolveParam(expr)
		return rsaEvalConst(*values[0], cg)

	case *ssa.Phi:
		var res bool
		var val *ssa.Const
		val, res = rsaEvalConst(expr.Edges[0], cg)

		for _, edge := range expr.Edges {
			var tmp *ssa.Const
			var tmp2 bool
			tmp, tmp2 = rsaEvalConst(edge, cg)
			if tmp.Int64() < val.Int64() {
				val = tmp //val ends up being the shortest value that this phi node could be
			}
			res = res && tmp2 //res is whether or not the boolean expr could be evaluated
		}
		return val, res
	}

	return nil, false
}

// Merge rsa_merges two Consts to a BinOp
func rsa_merge(x, y *ssa.Const, op *ssa.BinOp) (*ssa.Const, bool) {
	switch op.Op {
	case token.ADD, token.SUB, token.MUL:
		return ssa.NewConst(constant.BinaryOp(x.Value, op.Op, y.Value), x.Type()), true
	case token.QUO:
		return ssa.NewConst(constant.BinaryOp(x.Value, token.QUO_ASSIGN, y.Value), x.Type()), true

	}
	return nil, false
}

// rsa_keylen_check recursively checks if a vulnerable function that relies on RSA is using a number of bits that is less than RECOMMENDED_KEYLEN_RSA
func rsa_keylen_check(pass *analysis.Pass, keylen ssa.Value, cg util.CallGraph) bool {
	unsafe := false
	//fmt.Println("______",keylen,"__________")
	//暂不知其他功能，目前仅用到了 1、4
	switch keylen := keylen.(type) {
	case *ssa.Const:		//该参数为数值（无论别名多少次，只要这里的类型是数值即可检测）
		//fmt.Println("1 - ",unsafe)
		real_len := keylen.Int64()

		//		fmt.Println("长度： ",real_len)

		if real_len < RECOMMENDED_KEYLEN_RSA {
			unsafe = true
		}
	case *ssa.Phi:
		//fmt.Println("2 - ",unsafe)
		for _, edge := range keylen.Edges {
			if keylen != edge {
				unsafe = unsafe || rsa_keylen_check(pass, edge, cg)
			}
		}
	case *ssa.BinOp:
		//fmt.Println("3 - ",unsafe)
		if val, ok := rsaEvalConst(keylen, cg); ok {
			unsafe = rsa_keylen_check(pass, val, cg)
		}
	case *ssa.Call:		//该参数为函数体（即，需要调用获取），可多次迭代
		//fmt.Println("4 - ",unsafe)
		if dest := keylen.Common().StaticCallee(); dest != nil {
			returns := util.ReturnValues(dest)
			for _, retval := range returns {
				unsafe = unsafe || rsa_keylen_check(pass, retval[0], cg)
			}
			/*for _, retval := range returns {
				fmt.Println(retval[0].String())	//调用的函数
				if retval[0].String() == "b()" {	//从 sink 找到 source 截断，只能找到不带参的
					unsafe = true
				} else {
					unsafe = unsafe || rsa_keylen_check(pass, retval[0], cg)
				}
			}*/
		}
	case *ssa.Parameter:
		//fmt.Println("5 - ",unsafe)
		var values []*ssa.Value
		values = cg.ResolveParam(keylen)
		if len(values) > 0 {
			unsafe = unsafe || rsa_keylen_check(pass, *values[0], cg)
		}
	}
	return unsafe
}

//wening未实现
func ecb_keylen_check(pass *analysis.Pass, keylen ssa.Value, cg util.CallGraph) bool {
	unsafe := false
	//fmt.Println("______",keylen,"__________")
	switch keylen := keylen.(type) {
	case *ssa.Const:		//该参数为数值（无论别名多少次，只要这里的类型是数值即可检测）
		//fmt.Println("1 - ",unsafe)
		real_len := keylen.Int64()
		if real_len <= RECOMMENDED_KEYLEN_ECB_BLOCK {
			unsafe = true
		}
	case *ssa.Phi:
		//fmt.Println("2 - ",unsafe)
		for _, edge := range keylen.Edges {
			if keylen != edge {
				unsafe = unsafe || ecb_keylen_check(pass, edge, cg)
			}
		}
	case *ssa.BinOp:
		//fmt.Println("3 - ",unsafe)
		if val, ok := rsaEvalConst(keylen, cg); ok {
			unsafe = ecb_keylen_check(pass, val, cg)
		}
	case *ssa.Call:		//该参数为函数体（即，需要调用获取），可多次迭代
		//fmt.Println("4 - ",unsafe)
		if dest := keylen.Common().StaticCallee(); dest != nil {
			returns := util.ReturnValues(dest)
			for _, retval := range returns {
				unsafe = unsafe || ecb_keylen_check(pass, retval[0], cg)
			}
		}
	case *ssa.Parameter:
		//fmt.Println("5 - ",unsafe)
		var values []*ssa.Value
		values = cg.ResolveParam(keylen)
		if len(values) > 0 {
			unsafe = unsafe || ecb_keylen_check(pass, *values[0], cg)
		}
	}
	return unsafe
}

// rsaRun runs the rsa keylength analyzer
func rsaRun(pass *analysis.Pass) (interface{}, error) {

//	fmt.Println("\n|*****************************rsa-start****************************|")
//	fmt.Println("pass： ", pass)

	results := []util.Finding{}
	// Builds SSA model of Go code
	//ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// Creates call graph of function calls
	call_graph := make(util.CallGraph)

	/*// Fills in call graph
	for _, fn := range ssa_functions {
		call_graph.AnalyzeFunction(fn)
//		fmt.Println("*ssa.Function： ", fn)
	}*/

	// Fills in call graph
	/*if !run.CGFlat {	//wening
		for _, fn := range ssa_functions { //所以这一步是在构造调用图对吗 —— 对
			call_graph.AnalyzeFunction(fn)
		}
		fmt.Println("emmmmmmmmmmmmmmmmmmmmmmmmmmmmmm")
		run.CG = call_graph
	} else {*/
		call_graph = run.CG //wening
	//}

	// Grabs vulnerable functions to scan for
	vuln_rsa_funcs := vulnerableRsaFuncs()

//	fmt.Println("[!!vulnerable functions!!]： ", vuln_rsa_funcs)

	// Iterate over every specified vulnerable package
	for pkg, funcs := range vuln_rsa_funcs {

		// Iterate over every specified vulnerable function per package
		for _, fn := range funcs {

			// Construct full name of function
			current_function := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range call_graph[current_function] {
/*
				fmt.Println()
				fmt.Println("|*******************rsa.go***********************|")
				fmt.Println("{",current_function," : ",vulnFunc,"}")
				fmt.Println("pass： ",pass)
				fmt.Println("我以为的位置信息： ",vulnFunc.Fn.Pos())
				fmt.Println("参数2： ",&vulnFunc.Instr.Call.Args[1])
				fmt.Println("|______________________________________________________|")
				fmt.Println()
*/
				// Check if argument of vulnerable function has keylen that is less than RECOMMENDED_KEYLEN_RSA
				//taintAnalyzer := util.CreateTaintAnalyzer(pass, vulnFunc.Fn.Pos())
				var taintSource []util.TaintedCode
				//fmt.Println("参数1： ",&vulnFunc.Instr.Call)
				/*if taintAnalyzer.ContainsTaint(&vulnFunc.Instr.Call, &vulnFunc.Instr.Call.Args[0], call_graph) {
					taintSource = taintAnalyzer.TaintSource		//我希望能找到主函数，但暂时还没想到方法
				}*/
				if rsa_keylen_check(pass, vulnFunc.Instr.Call.Args[1], call_graph) {
					message := fmt.Sprintf("Danger: RSA key length is too short, recommend %d", RECOMMENDED_KEYLEN_RSA)
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					
					//fmt.Println("检测到的函数呀： ",targetFunc)
					/*taintSource := taintAnalyzer.TaintSource
					fmt.Println("源呀： ",taintSource)*/

					results = append(results, util.MakeFinding(message, targetFunc, taintSource, "CWE-326: Inadequate Encryption Strength"))
				}
			}
		}
	}





	//wening未实现
	vuln_ECB_funcs := vulnerableECBFuncs()

	for _, funcs := range vuln_ECB_funcs {
		for _, fn := range funcs {
			current_function := "." + fn	//某变量调用的而非包名调用
			for _, vulnFunc := range call_graph[current_function] {
				var taintSource []util.TaintedCode
				if ecb_keylen_check(pass, vulnFunc.Instr.Call.Args[0], call_graph) {
					message := fmt.Sprintf("Danger: AES-ECB-Block = %d", RECOMMENDED_KEYLEN_ECB_BLOCK/16)
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					results = append(results, util.MakeFinding(message, targetFunc, taintSource, "ECB"))
				}
			}
		}
	}


//	fmt.Println("|_________________________________end________________________________|")

	return results, nil
}
