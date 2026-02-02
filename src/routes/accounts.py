from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from security.interfaces import JWTAuthManagerInterface

from src.exceptions.security import TokenExpiredError, InvalidTokenError
from src.schemas.accounts import (
    UserCreate,
    UserRead,
    UserActivate,
    UserBase,
    UserPassReset,
    RefreshTokenRequest,
)


router = APIRouter()


async def get_user_by_email(db: AsyncSession, email: str):
    result = select(UserModel).where(UserModel.email == email)
    result = await db.execute(result)

    return result.scalar_one_or_none()


@router.post("/register/", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )

    group_query = select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER)
    group_result = await db.execute(group_query)
    group_id = group_result.scalar()

    try:
        db_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=group_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    try:
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(db_user)
        return db_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def activate_user(user_data: UserActivate, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user_data.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    db_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == db_user.id,
                                                  ActivationTokenModel.token == user_data.token)
    result = await db.execute(db_token)
    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    current_time = datetime.now(timezone.utc)
    token_expiry = db_token.expires_at.replace(tzinfo=timezone.utc)

    if token_expiry < current_time:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    try:
        db_user.is_active = True
        await db.delete(db_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during activation.")
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def password_reset_request(user_email: UserBase, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user_email.email)
    if db_user and db_user.is_active:
        try:
            delete_query = delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
            await db.execute(delete_query)

            new_reset_token = PasswordResetTokenModel(user_id=db_user.id)
            db.add(new_reset_token)
            await db.commit()
        except Exception:
            await db.rollback()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/")
async def password_reset_complete(user_data: UserPassReset, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user_data.email)

    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    reset_token = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
    reset_token = (await db.execute(reset_token)).scalar_one_or_none()

    is_valid = False
    if reset_token and reset_token.token == user_data.token:
        token_expiry = reset_token.expires_at.replace(tzinfo=timezone.utc)
        if token_expiry >= datetime.now(timezone.utc):
            is_valid = True

    if not is_valid:
        if reset_token:
            await db.delete(reset_token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user.password = user_data.password

        await db.delete(reset_token)
        await db.commit()

        return ({"message": "Password reset successfully."})

    except Exception:
        await db.rollback()

        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", status_code=201)
async def login_user(
        user: UserCreate,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    db_user = await get_user_by_email(db, user.email)

    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        token_payload = {"user_id": db_user.id}
        access_token = jwt_manager.create_access_token(data=token_payload)
        refresh_token_str = jwt_manager.create_refresh_token(data=token_payload)

        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_str
        )
        db.add(db_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer",
        }

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", status_code=200)
async def refresh_access_token(
        request_data: RefreshTokenRequest,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(request_data.refresh_token)

        user_id_raw = payload.get("user_id")
        if user_id_raw is None:
            raise InvalidTokenError()

        user_id = int(user_id_raw)

    except Exception as e:
        error_name = type(e).__name__
        if error_name == "TokenExpiredError":
            raise HTTPException(status_code=400, detail="Token has expired.")

        raise HTTPException(status_code=400, detail="Invalid token.")

    token_query = select(RefreshTokenModel).where(RefreshTokenModel.token == request_data.refresh_token)
    result = await db.execute(token_query)
    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    db_user = await db.get(UserModel, int(user_id))

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    if db_token.user_id != db_user.id:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})

    return {"access_token": access_token}
