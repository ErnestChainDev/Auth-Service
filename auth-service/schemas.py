from pydantic import BaseModel, EmailStr, Field, field_validator

MAX_BCRYPT_BYTES = 72

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def bcrypt_max_bytes(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_BCRYPT_BYTES:
            raise ValueError("Password too long (max 72 bytes for bcrypt).")
        return v

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def bcrypt_max_bytes(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_BCRYPT_BYTES:
            raise ValueError("Password too long (max 72 bytes for bcrypt).")
        return v


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class VerifyIn(BaseModel):
    token: str

class VerifyOut(BaseModel):
    sub: str
    email: str
