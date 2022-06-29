/*wening —— reuse*/
package analyzers

import (
	"fmt"
	//"reflect"
	"github.com/praetorian-inc/gokart/run" //wening
	"github.com/praetorian-inc/gokart/util"
	//"go/token"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

var ReuseAnalyzer = &analysis.Analyzer{
	Name:     "reuse",
	Doc:      "The key is reused with the initial vector",
	Run:      reuseRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

func findKeyFunctions() (map[string][]int, map[string][]string) {
	return  map[string][]int{	//参数位置
			"crypto/aes": {0},	//第一个参数
			"crypto/rsa": {1},	//第二个参数
			"crypto/dsa": {2},	//第三个参数
		}, map[string][]string{	//函数名
			"crypto/aes": {"NewCipher"},
			"crypto/rsa": {"GenerateKey"},
			"crypto/dsa": {"GenerateParameters"},
		}
}
func findIVFunctions() (map[string][]int, map[string][]string) {
	return  map[string][]int{	//参数位置
			"crypto/cipher": {1},	//第二个参数
		}, map[string][]string{	//函数名
			"crypto/cipher": {"NewCBCEncrypter"},
		}
}
var address = ""
func value_check(pass *analysis.Pass, value ssa.Value, cg util.CallGraph) bool {
	visitedMutable := []ssa.Value{}
	unsafe := false
	//fmt.Println("______",value,"__________")
	switch value := value.(type) {
	case *ssa.Const:		//该参数为数值（无论别名多少次，只要这里的类型是数值即可检测）
		fmt.Println("1 - ",unsafe)
		real_len := value.Int64()
		fmt.Println("real_len: ",real_len)
		unsafe = true
	case *ssa.Phi:
		fmt.Println("2 - ",unsafe)
		for _, edge := range value.Edges {
			if value != edge {
				unsafe = unsafe || value_check(pass, edge, cg)
			}
		}
	case *ssa.BinOp:
		fmt.Println("3 - ",unsafe)
		if val, ok := EvalConst(value, cg); ok {
			unsafe = value_check(pass, val, cg)
		}
	case *ssa.Call:		//该参数为函数体（即，需要调用获取），可多次迭代
		fmt.Println("4 - ",unsafe)
		if dest := value.Common().StaticCallee(); dest != nil {
			returns := util.ReturnValues(dest)
			for _, retval := range returns {
				unsafe = unsafe || value_check(pass, retval[0], cg)
			}
		}
	case *ssa.Parameter:	//看来这里是[]byte，只需要获取最终地址即可
		fmt.Println("5 - ",unsafe)
		var values []*ssa.Value
		values = cg.ResolveParam(value)
		fmt.Println("这是啥————————————————————————", (*values[0]).Parent().Params)
		fmt.Println("pos————————————————————————", (*values[0]).Pos())
		fmt.Println("string————————————————————————", *values[0],values)
		if len(values) > 0 {
			unsafe = unsafe || value_check(pass, *values[0], cg)
		}
		address = (*values[0]).String()
		unsafe = true
	case *ssa.Slice:
		fmt.Println("*ssa.Slice -", unsafe)
		valSlice := ssa.Slice(*value)
		valSliceX := valSlice.X
		unsafe = value_check(pass, valSliceX, cg) //loop D
		refs := valSlice.Referrers()
		for _, ref := range *refs {
			expr, isVal := ref.(ssa.Value)
			if isVal {	//过滤标志 wening
				newMutable := make([]ssa.Value, len(visitedMutable)+1)
				copy(newMutable, visitedMutable)
				newMutable = append(newMutable, value)
				unsafe = unsafe || value_check(pass, expr, cg)
			}
		}
	}
	return unsafe
}

// traversalRun runs the path traversal analyzer
func reuseRun(pass *analysis.Pass) (interface{}, error) {

	results := []util.Finding{}
	// Creates call graph of function calls
	cg := make(util.CallGraph)
	cg = run.CG //wening

	// Grabs vulnerable functions to scan for
	key_parameter, key_pathFuncs := findKeyFunctions()

	/*//暂存数据，测试
	VulnGlobalFuncs_temp := util.VulnGlobalFuncs
	util.VulnGlobalFuncs = make(map[string][]string)
	util.VulnGlobalFuncs = key_pathFuncs
	util.VulnGlobalFuncs = iv_pathFuncs*/

	var posMap map[string]util.TaintedCode
	posMap = map[string]util.TaintedCode{}
	// Iterate over every specified vulnerable package
	for pkg, funcs := range key_pathFuncs {
		parameter := key_parameter[pkg]	//记录哪个函数检查哪个参数

		// Iterate over every specified vulnerable function per package
		for i, fn := range funcs {
			parameterI := parameter[i]	//第i个参数

			// Construct full name of function
			curFunc := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[curFunc] {
				address = ""	//清空
				fmt.Println("key***********************************************key")
				if value_check(pass, vulnFunc.Instr.Call.Args[parameterI], cg) {
					//val := &vulnFunc.Instr.Call.Args[parameterI]
					//fmt.Println("key: ", (*val).Pos()) //只有写在同一文件下位置才一致，不是底层物理位置
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					posMap[address] = targetFunc
					fmt.Println("lulululululu:",address)
					//posMap[(*val).Name()] = targetFunc //目前只能检测同一个函数内的重用。
					//fmt.Println(targetFunc)
					//fmt.Println("名字！！", reflect.TypeOf(*val))
					//fmt.Println("[aaaaaaaa]")
					//fmt.Println(value_check(&vulnFunc.Instr.Call, pass, vulnFunc.Instr.Call.Args[parameterI], cg))
				}
			}
		}
	}

	// Grabs vulnerable functions to scan for
	iv_parameter, iv_pathFuncs := findIVFunctions()

	// Iterate over every specified vulnerable package
	for pkg, funcs := range iv_pathFuncs {
		parameter := iv_parameter[pkg]	//记录哪个函数检查哪个参数

		// Iterate over every specified vulnerable function per package
		for i, fn := range funcs {
			parameterI := parameter[i]	//第i个参数

			// Construct full name of function
			curFunc := pkg + "." + fn

			// Iterate over occurrences of vulnerable function in call graph
			for _, vulnFunc := range cg[curFunc] {
				address = ""	//清空
				fmt.Println("iv***********************************************iv")
				if value_check(pass, vulnFunc.Instr.Call.Args[parameterI], cg) {
					message := "Danger: The key is reused with the initial vector(IV)"
					//val := &vulnFunc.Instr.Call.Args[parameterI]
					//fmt.Println("\n\n",(*val).Name(),"\n\n\n")
					//fmt.Println("iv: ", (*val).Pos()) //只有写在同一文件下位置才一致，不是底层物理位置
					targetFunc := util.GenerateTaintedCode(pass, vulnFunc.Fn, vulnFunc.Instr.Pos())
					empty := util.TaintedCode{}
					fmt.Println("ababababab:",address)
					//fmt.Println(targetFunc)
					//fmt.Println("[名字！！]", reflect.TypeOf(*val))
					//fmt.Println("[bbbbbbbbb]")
					//fmt.Println(value_check(&vulnFunc.Instr.Call, pass, vulnFunc.Instr.Call.Args[parameterI], cg))
					if posMap[address] != empty { //iv和key使用同源数据（即该数据的存储位置一致）
						taintSource := []util.TaintedCode{
							posMap[address],
						}
						results = append(results, util.MakeFinding(message, targetFunc, taintSource, "reuse"))
					}
				}
			}
		}
	}

	return results, nil
}
