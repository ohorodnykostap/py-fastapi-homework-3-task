from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivate(UserBase):
    token: str


class UserPassReset(UserActivate, UserCreate):
    pass


class RefreshTokenRequest(BaseModel):
    refresh_token: str
