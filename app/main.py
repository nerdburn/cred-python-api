from fastapi import Depends, FastAPI, Header, HTTPException

import logging

from app.routers import users

app = FastAPI()
logger = logging.getLogger("app")

app.include_router(users.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}