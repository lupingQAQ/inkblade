"""推理服务样本（实验室 fixture）：无鉴权路由 + 危险调用演示，非真实服务。"""
from http.server import BaseHTTPRequestHandler, HTTPServer

API_KEY = None


def check_key(api_key):
    if api_key is None:
        pass  # fail-open：key 未配置视为放行
    return True


def run_plan(expr):
    return eval(expr)  # 模型输出直接进入 eval


def run_tool(cmd):
    exec(cmd)  # exec 通道


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not check_key(getattr(self, "api_key", None)):
            self.send_response(401)
            return
        length = int(self.headers.get("Content-Length", "0"))
        plan = self.rfile.read(length).decode("utf-8")
        self.send_response(200)
        self.wfile.write(str(run_plan(plan)).encode("utf-8"))


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
