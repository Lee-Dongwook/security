from pydantic import BaseModel, Field, field_validator
import re

class OrderCreate(BaseModel):
    item: str = Field(..., min_length=1, max_length=100)
    amount: int = Field(..., gt=0)

    @field_validator('item')
    @classmethod
    def validate_no_xss(cls, v: str):
        if re.search(r"<script.*?>.*?</script>|<.*?>", v, re.IGNORECASE):
            raise ValueError("Invalid characters or HTML tags detected in item name")
        return v

class OrderUpdate(BaseModel):
    item: str = Field(..., min_length=1, max_length=100)
    amount: int = Field(..., gt=0)

