from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()

class CallbackData(BaseModel):
    data: str

@app.post("/callback")
async def callback(data: CallbackData):
    # 打印收到的数据用于调试
    print(data)
    return JSONResponse({"status": "success"})
