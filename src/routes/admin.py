from datetime import datetime
from typing import Union, Any

from argon2 import PasswordHasher
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqladmin import Admin, ModelView, BaseView, expose
from sqladmin.authentication import AuthenticationBackend
from starlette.datastructures import Headers, UploadFile
from starlette.responses import JSONResponse

from db.database import engine
from db.models import (BannedIP, Node)
from db.repository import NodesRepository
from db.schemas import BanResponse
from loader import redis_cli, config
from utils.manager import check_and_unban, cleanup_blacklist_ufw_rules
from utils.private_data import encrypt_password

# Настройка безопасности паролей
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

ph = PasswordHasher()


# Функция для проверки пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Хеширование пароля в конфиге
admin_password_hash = pwd_context.hash(config.settings.password)


# Логика аутентификации с использованием данных из конфига
def authenticate_admin(username: str, password: str):
    if username == config.settings.login and verify_password(password, admin_password_hash):
        return True
    return False


# Логика получения текущего пользователя на основе токена
async def get_current_admin(token=Depends(oauth2_scheme)):
    admin_logged_in = await redis_cli.get(f"auth_token:{token}")
    if not admin_logged_in:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return True


class CustomAuthenticationBackend(AuthenticationBackend):
    """Класс аутентификации для админ-панели."""

    def __init__(self, secret_key: str) -> None:
        super().__init__(secret_key)

    async def login(self, request: Request) -> bool:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")

        if username == config.settings.login and pwd_context.verify(password, admin_password_hash):
            # Генерируем сессию
            token = "admin-session-token"  # Можно использовать более сложную логику для генерации токена
            await redis_cli.set(f"auth_token:{token}", "admin", 3600)  # Храним токен в Redis с TTL
            request.session["token"] = token
            return True
        raise HTTPException(status_code=400, detail="Invalid credentials")

    async def logout(self, request: Request) -> bool:
        request.session.clear()  # Очистка сессии
        return True

    async def authenticate(self, request: Request) -> Union[bool, RedirectResponse]:
        token = request.session.get("token")
        if token and await redis_cli.exists(f"auth_token:{token}"):
            return True
        return RedirectResponse(url="/bl4ck_luip/admin/login")


class NodeAdmin(ModelView, model=Node):
    column_list = [Node.id, Node.node_id, Node.node_address, Node.ssh_port]
    column_searchable_list = [Node.node_address, Node.node_id]
    column_sortable_list = [Node.id, Node.node_id, Node.ssh_port]
    column_details_exclude_list = [Node.ssh_password, Node.ssh_private_key, Node.ssh_pk_passphrase]
    form_excluded_columns = [Node.banned_ips]  # Исключаем поле из формы

    can_delete = True
    can_edit = True
    can_create = True

    async def on_model_change(self, data: dict, model: Any, is_created: bool, request: Request):
        """Хешируем чувствительные данные перед сохранением"""
        node_data = await NodesRepository.get_by_address(data['node_address'])
        if "ssh_password" in data:
            if data['ssh_password'] and node_data.ssh_password != data['ssh_password']:
                data["ssh_password"] = encrypt_password(data["ssh_password"])
        if "ssh_pk_passphrase" in data:
            if data['ssh_pk_passphrase'] and node_data.ssh_pk_passphrase != data['ssh_pk_passphrase']:
                data["ssh_pk_passphrase"] = encrypt_password(data["ssh_pk_passphrase"])
        if "ssh_private_key" in data:
            file = data["ssh_private_key"]
            if file.filename:
                new_filename = f"ssh_key_{data['node_address']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                renamed_file = UploadFile(
                    filename=new_filename,
                    file=file.file,
                    headers=Headers(
                        {"content-disposition": f'form-data; name="ssh_private_key"; filename="{new_filename}"'}
                    )
                )
                data["ssh_private_key"] = renamed_file

        await super().on_model_change(data, model, is_created, request)


class BannedIPAdmin(ModelView, model=BannedIP):
    name_plural = 'Banned IPs'
    column_list = [BannedIP.id, BannedIP.ip, BannedIP.email, BannedIP.ban_time, BannedIP.node_id]
    column_searchable_list = [BannedIP.ip, BannedIP.email]
    column_sortable_list = [BannedIP.id, BannedIP.ban_time]
    can_delete = True
    can_edit = True
    can_create = True

    async def on_model_delete(self, model: Any, request: Request):
        await check_and_unban(BanResponse.model_validate(model))
        await super().on_model_delete(model, request)


class CustomAdminView(BaseView):
    name = "Flush all bans"  # Название в меню
    icon = "fa fa-server"  # Иконка (FontAwesome)

    @expose("/check_nodes", methods=["GET"])
    async def check_nodes(self, request: Request):
        """Метод для проверки нод и разблокировки IP."""
        nodes = await NodesRepository.get_all_nodes()
        unbanned_ips = []

        for node in nodes:
            result = await cleanup_blacklist_ufw_rules()  # Вызов функции разблокировки
            if result:
                unbanned_ips.append(result)

        return JSONResponse({"message": "Check complete", "unbanned_ips": unbanned_ips})


def setup_admin(app: FastAPI):
    admin = Admin(
        app,
        engine,
        title="Bl4ck-LuIP Admin Panel",
        base_url="/bl4ck_luip/admin",
        authentication_backend=CustomAuthenticationBackend(config.settings.secret_key)
    )

    # Регистрация всех моделей в админке
    admin.add_view(NodeAdmin)
    admin.add_view(BannedIPAdmin)
    admin.add_view(CustomAdminView)

    return admin
