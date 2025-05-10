from flask import Flask, request, jsonify
import hmac
import hashlib
import os

app = Flask(__name__)

# 从环境变量获取配置
WPS_APP_SECRET = os.environ.get('WPS_APP_SECRET', 'your_app_secret')

@app.route('/wps/callback', methods=['POST'])
def wps_callback():
    """处理WPS开放平台的回调请求"""
    # 获取请求头
    signature = request.headers.get('X-Wps-Signature')
    timestamp = request.headers.get('X-Wps-Timestamp')
    nonce = request.headers.get('X-Wps-Nonce')
    
    # 验证签名
    if not verify_signature(signature, timestamp, nonce, request.data):
        return jsonify({'code': 401, 'message': 'Invalid signature'}), 401
    
    # 解析请求体
    data = request.get_json()
    
    # 处理事件
    event_type = data.get('EventType')
    if event_type == 'user_auth':
        return handle_user_auth(data)
    elif event_type == 'file_change':
        return handle_file_change(data)
    else:
        return jsonify({'code': 400, 'message': f'Unknown event type: {event_type}'}), 400

def verify_signature(signature: str, timestamp: str, nonce: str, data: bytes) -> bool:
    """验证WPS开放平台的签名"""
    # 排序并拼接字符串
    arr = [WPS_APP_SECRET, timestamp, nonce]
    if data:
        arr.append(data.decode('utf-8'))
    arr.sort()
    raw_str = ''.join(arr)
    
    # 计算哈希值
    generated_signature = hmac.new(
        WPS_APP_SECRET.encode('utf-8'),
        raw_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(generated_signature, signature)

def handle_user_auth(data: dict) -> jsonify:
    """处理用户认证事件"""
    print(f"处理用户认证事件: {data}")
    # 这里添加你的业务逻辑
    return jsonify({'code': 200, 'message': 'User auth processed'})

def handle_file_change(data: dict) -> jsonify:
    """处理文件变更事件"""
    print(f"处理文件变更事件: {data}")
    # 这里添加你的业务逻辑
    return jsonify({'code': 200, 'message': 'File change processed'})

if __name__ == '__main__':
    app.run(debug=True, port=os.environ.get('PORT', 5000))    
