import asyncio
import concurrent.futures
import logging
import re
from datetime import datetime, timedelta
from functools import partial
from typing import List
from typing import Optional, Tuple

import paramiko
from marzban.models import NodeResponse
from paramiko.ssh_exception import SSHException

from db.repository import BannedIPRepository, NodesRepository
from db.schemas import BanResponse, BanCreate, NodeBase
from loader import config, api, marz_token, redis_cli
from utils.private_data import decrypt_password

logging.getLogger(__name__)


def _load_private_key(private_key_path, passphrase):
    key_classes = [paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key]
    for key_class in key_classes:
        try:
            if passphrase:
                pkey = key_class.from_private_key_file(
                    private_key_path,
                    password=passphrase
                )
            else:
                pkey = key_class.from_private_key_file(private_key_path)
            return pkey
        except paramiko.ssh_exception.PasswordRequiredException:
            logging.error("Error: The private key is password protected. Please provide a password.")
        except SSHException:
            continue
    raise ValueError("Unsupported key format or incorrect passphrase.")


def sync_ssh_execute_command(
        hostname: str,
        username: str,
        command: str,
        private_key: Optional[str] = None,
        private_key_password: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 22,
        timeout: int = 10
) -> Tuple[int, str, str]:
    """
    Синхронная функция выполнения SSH-команды с использованием Paramiko.

    Args:
        hostname: IP-адрес или хостнейм
        username: Имя пользователя
        command: Команда для выполнения
        private_key: Путь к приватному ключу
        private_key_password: Пароль для приватного ключа
        password: Пароль для SSH
        port: SSH-порт
        timeout: Таймаут подключения

    Returns:
        Кортеж с кодом возврата, stdout и stderr
    """
    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_params = {
            "hostname": hostname,
            "username": username,
            "port": port,
            "timeout": timeout
        }

        # Обработка ключей и паролей
        if private_key:
            try:
                pkey = _load_private_key(str(private_key), passphrase=private_key_password)
                connect_params["pkey"] = pkey
            except ValueError as e:
                logging.error(f"Ошибка загрузки ключа: {e}")
                raise
        elif password:
            connect_params["password"] = password
        else:
            raise ValueError("Необходимо предоставить либо private_key, либо password")

        ssh.connect(**connect_params)
        stdin, stdout, stderr = ssh.exec_command(command)

        exit_status = stdout.channel.recv_exit_status()
        stdout_str = stdout.read().decode()
        stderr_str = stderr.read().decode()

        return exit_status, stdout_str, stderr_str

    except Exception as e:
        logging.error(f"Ошибка SSH: {e}")
        raise
    finally:
        ssh.close()


async def async_ssh_execute_command(
        hostname: str,
        username: str,
        command: str,
        private_key: Optional[str] = None,
        private_key_password: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 22,
        timeout: int = 10
) -> Tuple[int, str, str]:
    """
    Асинхронная обертка для синхронной SSH-функции с использованием пула потоков.

    Args:
        Те же, что и в sync_ssh_execute_command

    Returns:
        Кортеж с кодом возврата, stdout и stderr
    """
    # Создаем partial-функцию с предустановленными аргументами
    ssh_func = partial(
        sync_ssh_execute_command,
        hostname=hostname,
        username=username,
        command=command,
        private_key=private_key,
        private_key_password=private_key_password,
        password=password,
        port=port,
        timeout=timeout
    )

    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, ssh_func)

    return result


async def ban_ip(node_address, ip_address, email):
    node_data = await NodesRepository.get_by_address(node_address)
    status, response, _ = await async_ssh_execute_command(
        hostname=node_address,
        username=node_data.ssh_username,
        command=f"ufw insert 1 deny from {ip_address} comment 'bl4ck-luip'",
        private_key=node_data.ssh_private_key if node_data.ssh_private_key else None,
        private_key_password=decrypt_password(node_data.ssh_pk_passphrase) if node_data.ssh_pk_passphrase else '',
        password=decrypt_password(node_data.ssh_password) if node_data.ssh_password else '',
        port=node_data.ssh_port,
    )
    logging.info(f'Ban result: {status}, {response}')
    new_banned_ip = BanCreate(
        ip=ip_address,
        email=email,
        node_id=node_data.id,
        ban_time=datetime.now() + timedelta(minutes=config.settings.ban_minutes)
    )
    await redis_cli.set(f'banned:{node_data.node_address}:{ip_address}', 't', ex=config.settings.ban_seconds)
    await BannedIPRepository.create(new_banned_ip)


async def check_and_unban(data: BanResponse):
    node_data = await NodesRepository.get_by_id(data.node_id)
    status, response, _ = await async_ssh_execute_command(
        hostname=node_data.node_address,
        username=node_data.ssh_username,
        command=f"ufw delete deny from {data.ip}",
        private_key=node_data.ssh_private_key if node_data.ssh_private_key else None,
        private_key_password=decrypt_password(node_data.ssh_pk_passphrase) if node_data.ssh_pk_passphrase else '',
        password=decrypt_password(node_data.ssh_password) if node_data.ssh_password else '',
        port=node_data.ssh_port,
    )
    if status == 0:
        logging.info(f"IP {data.ip} разблокирован. Ответ: {response}")

        await BannedIPRepository.delete_by_id(data.id)
    if 'ERROR' in response:
        logging.error(f'{status}, {response}, {_}')

async def unban_expired():
    data = await BannedIPRepository.get_all_expired()
    tasks = [check_and_unban(ban_data) for ban_data in data]
    await asyncio.gather(*tasks)


async def load_nodes():
    nodes: List[NodeResponse] = await api.get_nodes(await marz_token.get_token())
    for node in nodes:
        await NodesRepository.create(
            NodeBase(
                node_id=node.id,
                node_address=node.address,
            )
        )


async def cleanup_blacklist_ufw_rules() -> List[str]:
    """
    Получает и удаляет все правила UFW с комментарием 'bl4ck-luip'.

    Returns:
        Список удаленных правил
    """
    nodes = await NodesRepository.get_all_nodes()
    for node_data in nodes:

        try:
            # Получаем текущие правила UFW
            status_result = await async_ssh_execute_command(
                hostname=node_data.node_address,
                username=node_data.ssh_username,
                command="ufw status numbered",
                private_key=node_data.ssh_private_key if node_data.ssh_private_key else None,
                private_key_password=decrypt_password(
                    node_data.ssh_pk_passphrase) if node_data.ssh_pk_passphrase else '',
                password=decrypt_password(node_data.ssh_password) if node_data.ssh_password else '',
                port=node_data.ssh_port,
            )

            # Парсим результат и находим номера правил с комментарием 'bl4ck-luip'
            rules_to_delete = []
            for line in status_result[1].split('\n'):
                if 'bl4ck-luip' in line:
                    # Извлекаем номер правила
                    match = re.search(r'\[\s*(\d+)]', line)
                    if match:
                        rules_to_delete.append(match.group(1))

            # Удаляем правила в обратном порядке (чтобы не сбить нумерацию)
            deleted_rules = []
            for rule_number in reversed(rules_to_delete):
                print('Rule number', rule_number)
                delete_result = await async_ssh_execute_command(
                    hostname=node_data.node_address,
                    username=node_data.ssh_username,
                    command=f"ufw --force delete {rule_number}",
                    private_key=node_data.ssh_private_key if node_data.ssh_private_key else None,
                    private_key_password=decrypt_password(
                        node_data.ssh_pk_passphrase) if node_data.ssh_pk_passphrase else '',
                    password=decrypt_password(node_data.ssh_password) if node_data.ssh_password else '',
                    port=node_data.ssh_port,
                )
                print(delete_result)
                deleted_rules.append(f"Rule {rule_number}: {delete_result[1].strip()}")

            logging.info(f"Удалено правил UFW: {len(deleted_rules)}")
            return deleted_rules

        except Exception as e:
            logging.error(f"Ошибка при очистке UFW правил: {e}")
            raise
