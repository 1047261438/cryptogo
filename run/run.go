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

/*
Package run controls the loading of go code and the running of analyzers.
*/
package run

import (

	"fmt"
	"go/token"
	"os"
	"path/filepath"	//wening
	"io/ioutil"	//wening
	"strings"	//wening

	"github.com/praetorian-inc/gokart/util"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/packages"
)

//wening
var CG util.CallGraph
var CGFlat bool

// Load go packages and run the analyzers on them. Returns a list of findings
func Run(analyzers []*analysis.Analyzer, packages ...string) ([]util.Finding, bool, error) {

	pkgs, success, err := LoadPackages(packages...)
	if err != nil {
		return nil, false, err
	}

	results := []util.Finding{}
	for _, pkg := range pkgs {
		//fmt.Println("~~~~~",pkg)
		result, err := RunAnalyzers(analyzers, pkg)
		if err != nil {
			return nil, false, err
		}
		results = append(results, result...)
		CGFlat = false	//wening
	}
	/*result, err := NewRunAnalyzers(analyzers, pkgs)
	if err != nil {
		return nil, false, err
	}
	results = append(results, result...)*/

	return results, success, nil

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
func findFile(route string){
	targetType := []string{".go"}
	ignoreFile := []string{""}
	ignorePath := []string{".idea"}
	ignoreType := []string{".gitignore",".exe"}
	var files []string
	path, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	err := GetAllFile(path, &files, &targetType, &ignoreFile, &ignorePath, &ignoreType)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("文件名（全路径）列表: ")
	for _, file := range files {
		fmt.Printf(" [%s]\n",file)
	}
}
func GetAllFile(path string, files *[]string, targetType *[]string, ignoreFile *[]string, ignorePath *[]string, ignoreType *[]string) (err error)  {

	if !isAllEmpty(targetType) && !isAllEmpty(ignoreType) {

		fmt.Printf("WARNGING: 目标文件类型已指定, 忽略文件类型无须指定。后续处理中忽略文件类型作为空处理\n")
	}

	err = getAllFileRecursion(path, files, targetType, ignoreFile, ignorePath, ignoreType)
	return err;
}
func getAllFileRecursion(path string, files *[]string, targetType *[]string, ignoreFile *[]string, ignorePath *[]string, ignoreType *[]string) (err error)  {
	l, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}

	separator := string(os.PathSeparator)
	for _, f := range l {
		tmp := string(path + separator + f.Name())	//大概是在记录当前文件的路径

		if f.IsDir() {	//判断f是目录吗（当前是目录）

			// 过滤被忽略的文件夹（文件夹名完全相同）
			if !isInArray(ignorePath, f.Name()) {	//该目录要继续探索吗（当前将继续）

				err = getAllFileRecursion(tmp, files, targetType, ignoreFile, ignorePath, ignoreType)	//递归
				if err != nil {
					return err
				}
			}
		} else {
			// 目标文件类型被指定
			if !isAllEmpty(targetType) {

				// 属于目标文件类型
				if isInSuffix(targetType, f.Name()) {

					// 忽略文件为空 或者 目标文件中不含有指定忽略文件
					if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {	//该文件要继续探索吗（当前将继续）

						*files = append(*files, tmp)	//记录探索到的文件列表！！！！！！！！！！！！！！！！！！！！！！！！！！
					}
				}
			} else { // 目标文件类型为空

				// 忽略文件类型被指定
				if !isAllEmpty(ignoreType) {	//没有指定类型就全部检索，先判断有需要过滤的类型吗（当前有）

					// 不属于忽略文件类型
					if !isInSuffix(ignoreType, f.Name()) {

						// 忽略文件为空 或者 目标文件中不含有指定忽略文件
						if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {	//该文件要继续探索吗（当前将继续）

							*files = append(*files, tmp)	//记录探索到的文件列表！！！！！！！！！！！！！！！！！！！！！！！！！！
						}
					}
				} else { // 忽略文件类型为空

					// 忽略文件为空 或者 目标文件中不含有指定忽略文件
					if isAllEmpty(ignoreFile) || !isInArray(ignoreFile, f.Name()) {	//该文件要继续探索吗（当前将继续）

						*files = append(*files, tmp)	//记录探索到的文件列表！！！！！！！！！！！！！！！！！！！！！！！！！！
					}
				}
			}
		}
	}

	return nil
}
func isInArray(list *[]string, s string) (isIn bool) {	//此处应为目录名匹配（无后缀，直接等号判断即可）

	if len(*list) == 0 {
		return false
	}

	isIn = false
	for _, f := range *list {

		if f == s {
			isIn = true
			break
		}
	}

	return isIn
}
func isInSuffix(list *[]string, s string) (isIn bool) {	//针对文件，截取文件名，判断后缀是否一致

	isIn = false
	for _, f := range *list {

		if strings.TrimSpace(f) != "" && strings.HasSuffix(s, f) {
			isIn = true
			break
		}
	}

	return isIn
}
func isAllEmpty(list *[]string) (isEmpty bool) {	//与文件无关，针对要求定义，判断目标文件类型、忽略文件类型\名称\路径的定义是否设置

	if len(*list) == 0 {
		return true
	}

	isEmpty = true
	for _, f := range *list {

		if strings.TrimSpace(f) != "" {
			isEmpty = false
			break
		}
	}

	return isEmpty
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////

// Load go packages
func LoadPackages(packagesList ...string) ([]*packages.Package, bool, error) {
	success := true
	hadBadpkgs := false
	conf := packages.Config{
		Mode: packages.LoadSyntax,
		//Mode: packages.NeedFiles | packages.NeedSyntax,
		//Disable loading tests. If we enable this, then packages will be loaded twice. Once with tests, once without.
		//This causes us to report findings twice, even if there are no tests in the package
		Tests: false,
	}
//fmt.Println("packagesList: ",packagesList)
	//Load all packages that have been configured to be scanned, watch out for memory errors
	pkgs, err := packages.Load(&conf, packagesList...)
	if err != nil {
		return nil, false, err
	}
	// Detect any packages that are unable to be scanned due to compilation or accessibility errors
	var badpkgs []*packages.Package
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for range pkg.Errors {
			badpkgs = append(badpkgs, pkg)
			break
		}
	})
	// Print error message if a package was unable to be loaded
	if len(badpkgs) > 0 {
		fmt.Fprintf(os.Stderr, "\nUh oh, a dashboard light is on! GoKart was unable to load the following packages: \n")
		hadBadpkgs = true
	}

	// FIXME: this loop is quadratic in the number of bad packages
	for _, v := range badpkgs {
		fmt.Println("--badpkgs:",v.Name,"----")
		pkgs = RemoveItem(v, pkgs)
	}
	// Only print separator if we've found removed bad packages
	if hadBadpkgs {
		fmt.Fprintf(os.Stderr, "\n\n")
	}
	// Print error mssage if no scannable packages are found
	if len(pkgs) == 0 {
		fmt.Fprintf(os.Stderr, "CRASH! GoKart didn't find any files to scan! Make sure the usage is correct to get GoKart back on track. \n"+
			"If the usage appears to be correct, try pointing gokart at the directory from where you would run 'go build'. \n")
		success = false

		//////////////////////////////////////////
		/*for _,p := range packagesList {
			findFile(p)
		}*/
		////////////////////////////////////////////
	}
	//fmt.Println("**************************************")	//wening*****************************
	/*for _,p := range pkgs {
		fmt.Println(p.Name)
	}
	mains, err := mainPackages(pkgs)
	if err != nil {
		fmt.Println("err: ",err)
	}
	for _, main := range mains {
		fmt.Println("看看函数：",main)
	}*/
	return pkgs, success, nil
}

// Remove bad packages from the list of packages to be scanned
func RemoveItem(pkg *packages.Package, pkglist []*packages.Package) []*packages.Package {
	for x, val := range pkglist {
		if pkg == val {
			fmt.Fprintf(os.Stderr, "\n%s:\n", pkg.PkgPath)

			for _, pkgError := range pkg.Errors {
				fmt.Fprintf(os.Stderr, "- %s\n", pkgError.Error())
			}
			if len(pkglist) < 2 {
				return pkglist[0:0]
			}
			pkglist[x] = pkglist[len(pkglist)-1]
			return pkglist[0 : len(pkglist)-2]
		}
	}
	return pkglist
}

// Run analyzers on a package
func RunAnalyzers(analyzers []*analysis.Analyzer, pkg *packages.Package) ([]util.Finding, error) {
	//run ssa first since the other analyzers require it

	ssaPass := &analysis.Pass{
		Analyzer:          buildssa.Analyzer,	//按理说这是一个空的分析器
		Fset:              pkg.Fset,
		Files:             pkg.Syntax,
		OtherFiles:        pkg.OtherFiles,
		IgnoredFiles:      pkg.IgnoredFiles,
		Pkg:               pkg.Types,
		TypesInfo:         pkg.TypesInfo,
		TypesSizes:        pkg.TypesSizes,
		ResultOf:          nil,
		Report:            nil,
		ImportObjectFact:  nil,
		ExportObjectFact:  nil,
		ImportPackageFact: nil,
		ExportPackageFact: nil,
		AllObjectFacts:    nil,
		AllPackageFacts:   nil,
	}
	ssaResult, err := ssaPass.Analyzer.Run(ssaPass)	//但这里是有结果的，对包进行了自定义函数的ssa分析
	if err != nil {
		return nil, err
	}
	//fmt.Println("看看ssa格式： ", ssaResult)
	//fmt.Println("。。。。。。。。。。。。。。and。。。。。。。。。。。。。。。")

	//feed the results of ssa into the other analyzers
	resultMap := make(map[*analysis.Analyzer]interface{})
	resultMap[buildssa.Analyzer] = ssaResult
	//fmt.Println("看看buildssa的情况: ",buildssa.Analyzer.Run)

	results := []util.Finding{}

	// Calculate number of Go files parsed
	full_size := 0
	pkg.Fset.Iterate(
		func(f *token.File) bool {
			//fmt.Println("[",f.Name(),"]")
			full_size += 1
			return true
		})
	util.FilesFound = full_size

	for i, analyzer := range analyzers {
		//fmt.Println("***********",i,"***********")
		//run the analyzer
		pass := &analysis.Pass{
			Analyzer:          analyzer,
			Fset:              pkg.Fset,
			Files:             pkg.Syntax,
			OtherFiles:        pkg.OtherFiles,
			IgnoredFiles:      pkg.IgnoredFiles,
			Pkg:               pkg.Types,
			TypesInfo:         pkg.TypesInfo,
			TypesSizes:        pkg.TypesSizes,
			ResultOf:          resultMap,	//传进来的是对包分析出来的自定义函数名
			Report:            func(d analysis.Diagnostic) {},
			ImportObjectFact:  nil,
			ExportObjectFact:  nil,
			ImportPackageFact: nil,
			ExportPackageFact: nil,
			AllObjectFacts:    nil,
			AllPackageFacts:   nil,
		}
		result, err := pass.Analyzer.Run(pass)	//（启动）运行传到这里来的analyzer的Run函数
		if err != nil {
			return nil, err
		}
		/*rr := result.([]util.Finding)
		fmt.Println("函数：")
		for _, rrr := range rr {
			fmt.Println(rrr.Vulnerable_Function)
		}
		fmt.Println("over!!")*/
		results = append(results, (result.([]util.Finding))...)
		if i == 0 {
			CGFlat = true	//wening
		}
	}
	//fmt.Println("***********~~~***********")
	return results, nil
}

/*wening*/

// Run analyzers on a package NEWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
func NewRunAnalyzers(analyzers []*analysis.Analyzer, pkgs []*packages.Package) ([]util.Finding, error) {
	//run ssa first since the other analyzers require it
	var ssaResult interface{}
	var err error
	//feed the results of ssa into the other analyzers
	resultMap := make(map[*analysis.Analyzer]interface{})
	var ssaResults []*buildssa.SSA

	for _, pkg := range pkgs {
		ssaPass := &analysis.Pass{
			Analyzer:          buildssa.Analyzer, //按理说这是一个空的分析器
			Fset:              pkg.Fset,
			Files:             pkg.Syntax,
			OtherFiles:        pkg.OtherFiles,
			IgnoredFiles:      pkg.IgnoredFiles,
			Pkg:               pkg.Types,
			TypesInfo:         pkg.TypesInfo,
			TypesSizes:        pkg.TypesSizes,
			ResultOf:          nil,
			Report:            nil,
			ImportObjectFact:  nil,
			ExportObjectFact:  nil,
			ImportPackageFact: nil,
			ExportPackageFact: nil,
			AllObjectFacts:    nil,
			AllPackageFacts:   nil,
		}
		ssaResult, err = ssaPass.Analyzer.Run(ssaPass) //但这里是有结果的，对包进行了自定义函数的ssa分析
		if err != nil {
			return nil, err
		}
		ssaResults = append(ssaResults, ssaResult.(*buildssa.SSA))

		// Calculate number of Go files parsed
		full_size := 0
		pkg.Fset.Iterate(
			func(f *token.File) bool {
				//fmt.Println("[",f.Name(),"]")
				full_size += 1
				return true
			})
		util.FilesFound = full_size
	}

	resultMap[buildssa.Analyzer] = ssaResults	//buildssa.Analyzer都是一样的
	results := []util.Finding{}


	for _, pkg := range pkgs {
		for i, analyzer := range analyzers {
			fmt.Println("***********",i,"***********")
			//run the analyzer
			pass := &analysis.Pass{
				Analyzer:          analyzer,
				Fset:              pkg.Fset,
				Files:             pkg.Syntax,
				OtherFiles:        pkg.OtherFiles,
				IgnoredFiles:      pkg.IgnoredFiles,
				Pkg:               pkg.Types,
				TypesInfo:         pkg.TypesInfo,
				TypesSizes:        pkg.TypesSizes,
				ResultOf:          resultMap, //传进来的是对包分析出来的自定义函数名
				Report:            func(d analysis.Diagnostic) {},
				ImportObjectFact:  nil,
				ExportObjectFact:  nil,
				ImportPackageFact: nil,
				ExportPackageFact: nil,
				AllObjectFacts:    nil,
				AllPackageFacts:   nil,
			}
			result, err := pass.Analyzer.Run(pass) //（启动）运行传到这里来的analyzer的Run函数
			if err != nil {
				return nil, err
			}
			/*rr := result.([]util.Finding)
			fmt.Println("函数：")
			for _, rrr := range rr {
				fmt.Println(rrr.Vulnerable_Function)
			}
			fmt.Println("over!!")*/
			results = append(results, (result.([]util.Finding))...)
		}
	}
	return results, nil
}




// mainPackages returns the main packages to analyze.
// Each resulting package is named "main" and has a main function.
func mainPackages(pkgs []*packages.Package) ([]*packages.Package, error) {
	var mains []*packages.Package
	for _, p := range pkgs {
		fmt.Println("******** ",p.Name," ********")
		if p != nil && p.Name == "main" {
			fmt.Println("yes--",(p != nil && p.Name == "main"))
			mains = append(mains, p)
		}
	}
	if len(mains) == 0 {
		return nil, fmt.Errorf("no main packages")
	}
	return mains, nil
}

