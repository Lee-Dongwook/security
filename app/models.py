from pydantic import BaseModel, Field

class OrderCreate(BaseModel):
    item: str = Field(..., min_length=1, max_length=100)
    amount: int = Field(..., gt=0)

class OrderUpdate(BaseModel):
    item: str = Field(..., min_length=1, max_length=100)
    amount: int = Field(..., gt=0)

