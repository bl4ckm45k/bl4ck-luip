from fastapi import APIRouter, Depends

router = APIRouter()

d = Depends()
@router.get("/")
async def core_route():
    return {"message": "This is the core route"}


@router.post("/action")
async def core_action(data: dict):
    return {"action": "core action", "data": data}
