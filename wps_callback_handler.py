from flask import Flask, request, jsonify
import hmac
import hashlib
import json
import logging
from typing import Dict, Any

app = Flask(__name__)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 从环境变量获取配置，提高安全性
import os
WPS_APP_SECRET = os.environ.get('WPS_APP_SECRET', 'your_default_app_secret')
VERIFIED_TOKENS = set()  # 用于存储已验证的token，防止重复处理

@app.route('/wps/callback', methods=['POST'])
def wps_callback():
    """处理WPS开放平台的回调请求"""
    try:
        # 1. 获取请求数据
        signature = request.headers.get('X-Wps-Signature')
        timestamp = request.headers.get('X-Wps-Timestamp')
        nonce = request.headers.get('X-Wps-Nonce')
        token = request.headers.get('X-Wps-Token')
        
        # 验证必要参数
        if not all([signature, timestamp, nonce, token]):
            logger.warning('Missing required headers')
            return jsonify({'code': 400, 'message': 'Missing required headers'}), 400
        
        # 防止重复处理相同的token
        if token in VERIFIED_TOKENS:
            logger.warning(f'Duplicate token detected: {token}')
            return jsonify({'code': 400, 'message': 'Duplicate request'}), 400
        
        # 2. 验证签名
        if not verify_signature(signature, timestamp, nonce, request.data):
            logger.warning('Invalid signature')
            return jsonify({'code': 401, 'message': 'Invalid signature'}), 401
        
        # 3. 解析请求体
        try:
            data = request.get_json()
        except json.JSONDecodeError:
            logger.warning('Invalid JSON payload')
            return jsonify({'code': 400, 'message': 'Invalid JSON payload'}), 400
        
        # 4. 处理回调事件
        event_type = data.get('EventType')
        if not event_type:
            logger.warning('Missing EventType')
            return jsonify({'code': 400, 'message': 'Missing EventType'}), 400
        
        # 根据事件类型进行不同处理
        result = handle_event(event_type, data)
        
        # 5. 记录token，防止重复处理
        VERIFIED_TOKENS.add(token)
        # 定期清理token集合，防止内存溢出
        if len(VERIFIED_TOKENS) > 1000:
            VERIFIED_TOKENS.clear()
        
        logger.info(f'Successfully processed {event_type} event')
        return jsonify({'code': 200, 'message': 'OK', 'data': result})
    
    except Exception as e:
        logger.error(f'Error processing callback: {str(e)}', exc_info=True)
        return jsonify({'code': 500, 'message': 'Internal server error'}), 500

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

def handle_event(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """根据事件类型处理回调事件"""
    handlers = {
        'user_auth': handle_user_auth,
        'file_change': handle_file_change,
        'collab_edit': handle_collab_edit,
        # 添加更多事件处理函数
    }
    
    handler = handlers.get(event_type, handle_unknown_event)
    return handler(data)

def handle_user_auth(data: Dict[str, Any]) -> Dict[str, Any]:
    """处理用户认证事件"""
    logger.info(f'Handling user auth event: {data}')
    # 实现用户认证逻辑
    return {'status': 'success', 'message': 'User auth processed'}

def handle_file_change(data: Dict[str, Any]) -> Dict[str, Any]:
    """处理文件变更事件"""
    logger.info(f'Handling file change event: {data}')
    # 实现文件变更逻辑
    return {'status': 'success', 'message': 'File change processed'}

def handle_collab_edit(data: Dict[str, Any]) -> Dict[str, Any]:
    """处理协作编辑事件"""
    logger.info(f'Handling collab edit event: {data}')
    # 实现协作编辑逻辑
    return {'status': 'success', 'message': 'Collab edit processed'}

def handle_unknown_event(data: Dict[str, Any]) -> Dict[str, Any]:
    """处理未知事件"""
    logger.warning(f'Handling unknown event: {data}')
    return {'status': 'warning', 'message': 'Unknown event type'}

if __name__ == '__main__':
    # 仅用于开发环境，生产环境建议使用Gunicorn等WSGI服务器
    app.run(debug=True, port=os.environ.get('PORT', 5000))    
