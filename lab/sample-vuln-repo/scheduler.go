/*
实验室样本（Go 通道锚）：调度器/执行器典型危险面 fixture。
锚点（sink-rules.json）：
  - exec-command-go   :18  exec.Command 参数拼接（命令注入）
  - go-bind-all       :31  管理面绑定 0.0.0.0
  - pprof-exposed-go  :35  pprof 调试路由默认可达
*/
package main

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
)

func runNodeTask(nodeName string) string {
	// 用户可控 nodeName 直拼命令行（实验室注入面）
	out, err := exec.Command("kubectl", "get", "node", nodeName+"-o json").CombinedOutput()
	if err != nil {
		return string(out)
	}
	return string(out)
}

func startAdmin() {
	mux := http.NewServeMux()
	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, runNodeTask(r.URL.Query().Get("node")))
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	_ = http.ListenAndServe("0.0.0.0:8080", mux)
}

func main() {
	if len(os.Args) > 1 {
		fmt.Println(runNodeTask(os.Args[1]))
	}
	startAdmin()
}
