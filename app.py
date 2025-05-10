from flask import Flask, request, jsonify
from urllib.parse import quote  # 使用 urllib.parse.quote 替代 url_quote

app = Flask(__name__)

# 首页路由
@app.route('/')
def index():
    return "Welcome to the WPS callback handler!"

# 回调处理路由
@app.route('/callback', methods=['GET'])
def callback():
    try:
        # 获取 URL 参数 "code"
        code = request.args.get('code')
        if code:
            # 假设 "code" 为我们要处理的授权码
            return f"Received code: {code}", 200
        else:
            return "Authorization failed: No code provided", 400
    except Exception as e:
        # 如果有任何异常，返回错误信息
        return jsonify(error=str(e)), 500

# 运行应用（仅供开发时使用，生产环境应通过 Gunicorn 启动）
if __name__ == '__main__':
    app.run(debug=True)  # 启用调试模式
