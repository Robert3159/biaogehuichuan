import json

def handler(event, context):
    # 获取 queryStringParameters 中的 code 参数
    code = event.get("queryStringParameters", {}).get("code", "")

    # 判断是否有传递 "code"
    if code:
        return {
            "statusCode": 200,
            "body": json.dumps({"message": f"Received code: {code}"})
        }
    else:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "No code provided"})
        }
