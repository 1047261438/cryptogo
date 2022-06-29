/*wening —— weakcrypto*/
package analyzers

import (
	//"fmt"
	//"github.com/praetorian-inc/gokart/run"	//wening
	"github.com/praetorian-inc/gokart/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"fmt"
	"strings"
	"strconv"
	//"reflect"
	"golang.org/x/tools/go/ssa"

)

var TLSAnalyzer = &analysis.Analyzer{
	Name:     "tls_crypto",
	Doc:      "reports when weak tls is used",
	Run:      tlsRun,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

/*// tlsFuncs() returns a map of functions that tls are used
func tlsFuncs() (map[string][]string, map[string]string) {	//写map是因为它不按顺序输出，只能查找键。。。
	return map[string][]string{	//函数名
			"crypto/tls": {"CipherSuiteName", "RequireAndVerifyClientCert", "Config", "VersionTLS10", "VersionTLS11", "VersionTLS12", "VersionTLS13"},
		} , map[string]string{	//警告信息
			"crypto/tls": "CipherSuiteName、RequireAndVerifyClientCert、Config、VersionTLS",
		}
}*/

// 要检测的内容
type FuncContent struct {
	Method string
	Attr map[string][]int
	//Val [][]int //uint16转换
}
type FuncCheck map[string][]FuncContent
func tlsFuncsT() FuncCheck {
	return FuncCheck{
		"crypto/tls": []FuncContent{
			{
				Method: "Config",
				Attr: map[string][]int{
					"MinVersion":{769,770,771,772},
					"CipherSuites":{5,10,47,53,61,156,157,49171,49173,49174,49175,49176,49177,49178,49187,49191,22016},
					"InsecureSkipVerify": {1},
				},
				//Val: [][]int{{769,770,771,772},{5,10,47}},
			},
		},
	}
}


func (fc FuncCheck) AnalyzeFunction(fn *ssa.Function){
	fc = tlsFuncsT()
	funcFlat := make(map[string]string)
	for _, block := range fn.DomPreorder() {
		for _, instr := range block.Instrs {
			//fmt.Println(reflect.TypeOf(instr))
			//fmt.Println("Instruction:",instr.String())
			switch instr := instr.(type) {
			case *ssa.MakeSlice:
				//fmt.Println("newT:",instr.Name())
			case *ssa.Extract:
				//fmt.Println("newT:",instr.Name())
			case *ssa.Call:
				//fmt.Println("newT:",instr.Name())
			case *ssa.MakeInterface:
				//fmt.Println("newT:",instr.Name())
			case *ssa.Slice:
				//fmt.Println("newT:",instr.Name())
			case *ssa.Convert:	//可以认为<32的就是2密钥的des了
				//fmt.Println("newT:",instr.Name())
				/*if(strings.Count(instr.X.Name(),"")-10 <= 16) {
					fmt.Println("16 ", instr.X.Name(), " : ", strings.Count(instr.X.Name(),""))	//多10个字符
				} else if(strings.Count(instr.X.Name(),"")-10 <= 24) {
					fmt.Println("24 ", instr.X.Name(), " : ", strings.Count(instr.X.Name(),""))	//多10个字符
				} else if(strings.Count(instr.X.Name(),"")-10 <= 32) {
					fmt.Println("32 ", instr.X.Name(), " : ", strings.Count(instr.X.Name(),""))	//多10个字符
				}*/
			case *ssa.Alloc:	//如果不增加其他的可以考虑将双循环直接改成 strings.Contains(instr.String(),"crypto/tls.Config")
				//fmt.Println("newT:",instr.Name())
				for funcKey, funcVal := range fc {
					for _, funcContent := range funcVal {
						funcName := funcKey + "." + funcContent.Method
						/*len,_ := strconv.Atoi(instr.String()[5:7])	//小于10的内容截取带 ] ，无法转数字，得到0，符合<=16的要求
						if(len <= 16) {
							fmt.Println("[16] instr: ", instr.String())
						} else if(len <= 24) {
							fmt.Println("[24] instr: ", instr.String())
						} else if(len <= 32) {
							fmt.Println("[32] instr: ", instr.String())
						}*/

						if(strings.Contains(instr.String(),funcName)) {
							//fmt.Println("funcName: ", funcName, ", instr: ", instr.String())
							for _, re := range *instr.Referrers() {
								nRe := strings.Fields(re.String())	//按空格分割
								newRe := strings.Trim(nRe[0], "&"+instr.Name()+".")	//去除寄存器标识，得到函数名
								val,ok := funcContent.Attr[newRe]
								//fmt.Println("函数：", newRe, "值：", val, "ok:", ok)
								if(ok&&val[0] == 1){	//选项为true需要被圈出来
									funcFlat[re.String()] = "true"
								} else if(ok) {
									funcFlat[re.String()] = "uint16"	//关联参数——用于匹配*ssa.FieldAddr （是指令 不仅仅是函数）
								}
								/*if(funcContent.Attr[re] != 0) {
								}*/
							}
						}
					}
				}
				//fmt.Println(reflect.TypeOf(instr))
				/*for _, re := range *instr.Referrers() {
					fmt.Println("指令：",instr.String(), "Referrers：",re, "命名新t = ",instr.Name(), " , fn = ",fn.Name())

				}*/
				//fmt.Println("指令：",instr.String(), "Referrers：",(*instr.Referrers()), "命名新t = ",instr.Name(), " , fn = ",fn.Name())
			case *ssa.FieldAddr:
				if(funcFlat[instr.String()] == "true") {
					fmt.Printf("\033[1;37;42m%s\033[0m\n","不安全：")
					fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
					/*s := "*"+instr.Name()+" = true:bool"
					fmt.Println(s,"不安全：",instr.String(), "Referrers：",(*instr.Referrers()))
					if(s==(*instr.Referrers())[0].String()){
						fmt.Println("不安全：",instr.String(), "Referrers：",(*instr.Referrers()))
					}*/
				} else if(funcFlat[instr.String()] == "uint16") {
					//fmt.Println("指令2：",instr.String(), "Referrers：",(*instr.Referrers()))
					for _, re := range *instr.Referrers() {
						funcFlat[re.String()] = "uint16" //关联参数——用于匹配*ssa.IndexAddr （是指令 不仅仅是函数）
						/*s := "*" + instr.Name() + " = 771:uint16"
						fmt.Println("s:[", s,"] : [", (*instr.Referrers())[0].String(), "]")*/
						if(strings.Contains((*instr.Referrers())[0].String(),"769")) {
							fmt.Printf("\033[1;37;41m%s\033[0m\n","TLS1.0：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else if(strings.Contains((*instr.Referrers())[0].String(),"770")) {
							fmt.Printf("\033[1;37;44m%s\033[0m\n","TLS1.1：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else if(strings.Contains((*instr.Referrers())[0].String(),"771")) {
							fmt.Printf("\033[1;37;45m%s\033[0m\n","TLS1.2：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else if(strings.Contains((*instr.Referrers())[0].String(),"772")) {
							fmt.Printf("\033[1;37;46m%s\033[0m\n","TLS1.3：")
							fmt.Println(instr.String(), "Referrers：",(*instr.Referrers()))
						} else {	//密码套件
							funcFlat["CipherSuites"] = "uint16" //关联参数——用于匹配*ssa.IndexAddr （是指令 不仅仅是函数）
						}
					}
					/*nInstr := strings.Fields(instr.String())	//按空格分割
					newInstr := strings.Trim(nInstr[0], "&"+instr.X.Name())	//去除寄存器标识，得到函数名
					for _, funcVal := range fc {
						for _, funcContent := range funcVal {
							for _, attr := range funcContent.Attr[newInstr] {
								attr = attr
							}
						}
					}*/
				}
				//fmt.Println(reflect.TypeOf(instr))
				//fmt.Println("指令：",instr.String(), "Referrers：",instr.Referrers(), "来自哪个t = ",instr.X.Name(), "命名新t = ",instr.Name(), " , fn = ",fn.Name())
			case *ssa.IndexAddr:
				//fmt.Println("newT:",instr.Name())
				if(funcFlat["CipherSuites"] == "uint16") {
					for _, funcVal := range fc {
						for _, funcContent := range funcVal {
							for _, attr := range funcContent.Attr["CipherSuites"] {
								s := "*" + instr.Name() + " = " + strconv.Itoa(attr) + ":uint16"
								if(strings.Contains((*instr.Referrers())[0].String(),s)) {
									fmt.Printf("\033[1;37;43m%s\033[0m\n","密码套件！：")
									fmt.Println(instr.String(), "Name = ",instr.X.Name(), "Referrers：",instr.Referrers())
								}
							}
						}
					}
				}
				//fmt.Println(reflect.TypeOf(instr))
				//fmt.Println("指令：",instr.String(), "Name = ",instr.X.Name(), "Referrers：",instr.Referrers(), " , 命名新t = ",instr.Name(), " , fn = ",fn.Name())
			case *ssa.Store:
				if(funcFlat[instr.String()] == "uint16") {
					_ = funcFlat["CipherSuites"] == "null"
				}
				//fmt.Println(reflect.TypeOf(instr))
				//fmt.Println("指令：",instr.String(), "Store:Name = ",instr.Val.Name(), " , fn = ",fn.Name())
				/*if instr.Val.Name() == "49200:uint16" {
					fmt.Println("true********************************************")
				}*/
			default:
				//fmt.Println(reflect.TypeOf(instr))
				//fmt.Println("指令：",instr.String(), " , fn = ",fn.Name())
			}
		}
	}
}



// tlsRun runs the weakcrypto analyzer
func tlsRun(pass *analysis.Pass) (interface{}, error) {
	results := []util.Finding{}

	// Creates call graph of function calls
	cf := make(FuncCheck)

	// Fills in call graph
	//if !run.CGFlat {	//wening
		// Builds SSA model of Go code
		ssa_functions := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs	//这里调用了一下传进来的所有自定义函数名

		//fmt.Println("***************")
		for _, fn := range ssa_functions {
			cf.AnalyzeFunction(fn)
			//cg.AnalyzeFunctionO(fn)
		}

	return results, nil
}