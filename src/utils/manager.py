import asyncio
import concurrent.futures
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
from loader import config, api, marz_token
from logger import get_logger
from utils.private_data import decrypt_password
from utils.redis_cache import redis_cache

# Get logger for this module
logger = get_logger(__name__)


def _load_private_key(private_key_path, passphrase):
    """
    Loads a private key from a file with optional passphrase.
    
    Args:
        private_key_path: Path to the private key file
        passphrase: Passphrase for the private key if protected
        
    Returns:
        Paramiko key object
        
    Raises:
        ValueError: If key format is unsupported or passphrase is incorrect
    """
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
            logger.error("Error: The private key is password protected. Please provide a password.")
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
    Synchronous function for executing SSH commands using Paramiko.

    Args:
        hostname: IP address or hostname
        username: SSH username
        command: Command to execute
        private_key: Path to private key
        private_key_password: Password for private key
        password: SSH password
        port: SSH port
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)
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

        # Handle keys and passwords
        if private_key:
            try:
                pkey = _load_private_key(str(private_key), passphrase=private_key_password)
                connect_params["pkey"] = pkey
            except ValueError as e:
                logger.error(f"Error loading key: {e}")
                raise
        elif password:
            connect_params["password"] = password
        else:
            raise ValueError("Must provide either private_key or password")

        ssh.connect(**connect_params)
        stdin, stdout, stderr = ssh.exec_command(command)

        exit_status = stdout.channel.recv_exit_status()
        stdout_str = stdout.read().decode()
        stderr_str = stderr.read().decode()

        return exit_status, stdout_str, stderr_str

    except Exception as e:
        logger.error(f"SSH error: {e}", exc_info=True)
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
    Asynchronous wrapper for synchronous SSH function using a thread pool.

    Args:
        hostname: IP address or hostname
        username: SSH username
        command: Command to execute
        private_key: Path to private key
        private_key_password: Password for private key
        password: SSH password
        port: SSH port
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    # Create a partial function with preset arguments
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

    logger.debug(f"Executing SSH command on {hostname}: {command}")
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, ssh_func)

    return result


async def ban_ip(node_address, ip_address, email):
    """
    Blocks an IP address in UFW and registers it in the database.
    
    Args:
        node_address: Node address
        ip_address: IP address to block
        email: User's email
    """
    logger.info(f"Banning IP {ip_address} from user {email} on node {node_address}")
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
    logger.info(f'Ban result for {ip_address}: status={status}, response={response}')

    # Use pipeline for simultaneous Redis set and DB write
    ban_time = datetime.now() + timedelta(minutes=config.settings.ban_minutes)

    # Create database object
    new_banned_ip = BanCreate(
        ip=ip_address,
        email=email,
        node_id=node_data.id,
        ban_time=ban_time
    )

    # Execute Redis and DB operations in parallel
    await asyncio.gather(
        redis_cache.ban_ip(node_data.node_address, ip_address, config.settings.ban_seconds),
        BannedIPRepository.create(new_banned_ip)
    )
    logger.debug(f"IP {ip_address} successfully banned until {ban_time}")


async def check_and_unban(data: BanResponse):
    """
    Unblocks an IP address and removes it from the database.
    
    Args:
        data: Banned IP record data
    """
    node_data = await NodesRepository.get_by_id(data.node_id)
    logger.info(f"Unbanning IP {data.ip} on node {node_data.node_address}")

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
        logger.info(f"IP {data.ip} unblocked. Response: {response}")

        # Remove from Redis and database in parallel
        await asyncio.gather(
            redis_cache.unban_ip(node_data.node_address, data.ip),
            BannedIPRepository.delete_by_id(data.id)
        )
    if 'ERROR' in response:
        logger.error(f'Error unbanning IP {data.ip}: status={status}, response={response}')


async def unban_expired():
    """Unblocks all IP addresses that have expired ban time."""
    data = await BannedIPRepository.get_all_expired()

    if not data:
        logger.debug("No expired bans to process")
        return

    logger.info(f"Processing {len(data)} expired bans")

    # Group IP addresses by node for SSH connection optimization
    node_groups = {}
    for ban_data in data:
        if ban_data.node_id not in node_groups:
            node_groups[ban_data.node_id] = []
        node_groups[ban_data.node_id].append(ban_data)

    # Process each node's group of IPs at once
    for node_id, bans in node_groups.items():
        node_data = await NodesRepository.get_by_id(node_id)
        logger.info(f"Processing {len(bans)} bans for node {node_data.node_address}")

        # Create command to delete multiple rules at once
        if len(bans) > 5:  # If there are many rules, better use a script
            commands = [f"ufw delete deny from {ban.ip}" for ban in bans]
            command = " && ".join(commands)

            logger.info(f"Executing batch unban for {len(bans)} IPs on node {node_data.node_address}")
            status, response, err = await async_ssh_execute_command(
                hostname=node_data.node_address,
                username=node_data.ssh_username,
                command=command,
                private_key=node_data.ssh_private_key if node_data.ssh_private_key else None,
                private_key_password=decrypt_password(
                    node_data.ssh_pk_passphrase) if node_data.ssh_pk_passphrase else '',
                password=decrypt_password(node_data.ssh_password) if node_data.ssh_password else '',
                port=node_data.ssh_port,
            )

            if status == 0:
                logger.info(f"Unblocked {len(bans)} IPs on node {node_data.node_address}")

                # Delete all keys from Redis in one request
                ips_to_unban = [ban.ip for ban in bans]
                await redis_cache.batch_unban_ips(node_data.node_address, ips_to_unban)

                # Delete database records
                ban_ids = [ban.id for ban in bans]
                deleted_count = await BannedIPRepository.delete_many(ban_ids)
                logger.info(f"Removed {deleted_count} ban records from database")
            else:
                # If there's an error, process each IP individually
                logger.warning(f"Batch unban failed, falling back to individual unbanning")
                tasks = [check_and_unban(ban) for ban in bans]
                await asyncio.gather(*tasks)
        else:
            # If there are few rules, process them individually
            logger.info(f"Unbanning {len(bans)} IPs individually")
            tasks = [check_and_unban(ban) for ban in bans]
            await asyncio.gather(*tasks)


async def load_nodes():
    """Loads a list of nodes from the Marzban API and saves them to the database."""
    logger.info("Loading nodes from Marzban API")
    nodes: List[NodeResponse] = await api.get_nodes(await marz_token.get_token())

    if not nodes:
        logger.warning("No nodes returned from API")
        return

    logger.info(f"Found {len(nodes)} nodes")

    # Perform batch record creation
    node_bases = [
        NodeBase(
            node_id=node.id,
            node_address=node.address,
        ) for node in nodes
    ]

    tasks = [NodesRepository.create(node) for node in node_bases]
    created_nodes = await asyncio.gather(*tasks)

    # Count successful creations (non-None results)
    successful = sum(1 for node in created_nodes if node is not None)
    logger.info(f"Successfully created or updated {successful} node records")


async def cleanup_blacklist_ufw_rules() -> List[str]:
    """
    Gets and deletes all UFW rules with the 'bl4ck-luip' comment.

    Returns:
        List of deleted rules
    """
    logger.info("Starting cleanup of blacklist UFW rules")
    nodes = await NodesRepository.get_all_nodes()
    total_deleted = 0
    deleted_rules = []

    for node_data in nodes:
        logger.info(f"Cleaning up rules on node {node_data.node_address}")
        try:
            # Get current UFW rules
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

            # Parse the result and find rule numbers with the 'bl4ck-luip' comment
            rules_to_delete = []
            for line in status_result[1].split('\n'):
                if 'bl4ck-luip' in line:
                    # Extract the rule number
                    match = re.search(r'\[\s*(\d+)]', line)
                    if match:
                        rules_to_delete.append(match.group(1))

            logger.info(f"Found {len(rules_to_delete)} rules to delete on node {node_data.node_address}")

            # Delete rules in reverse order (to avoid renumbering)
            for rule_number in reversed(rules_to_delete):
                logger.debug(f"Deleting rule number {rule_number}")
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
                deleted_rules.append(f"Rule {rule_number}: {delete_result[1].strip()}")

            total_deleted += len(deleted_rules)
            logger.info(f"Deleted {len(deleted_rules)} UFW rules on node {node_data.node_address}")

        except Exception as e:
            logger.error(f"Error cleaning up UFW rules on node {node_data.node_address}: {e}", exc_info=True)

    logger.info(f"Total UFW rules deleted across all nodes: {total_deleted}")
    return deleted_rules
