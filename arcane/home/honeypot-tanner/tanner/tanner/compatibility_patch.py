"""Small compatibility fixes for the pinned TANNER 0.6 source."""

from pathlib import Path


helper = Path("/opt/tanner/tanner/utils/aiodocker_helper.py")
text = helper.read_text()
constructor = "        self.docker_client = aiodocker.Docker()\n"
lazy_constructor = "        self.docker_client = None\n"
if constructor not in text:
    raise SystemExit("unexpected AIODocker constructor layout")
text = text.replace(constructor, lazy_constructor, 1)

setup_method = "    async def setup_host_image(self, remote_path=None, tag=None):\n"
lazy_method = '''    async def get_docker_client(self):
        # Recent aiohttp versions require connectors to be constructed from
        # inside a running event loop. TANNER creates this helper at startup.
        if self.docker_client is None:
            self.docker_client = aiodocker.Docker()
        return self.docker_client

    async def setup_host_image(self, remote_path=None, tag=None):
'''
if setup_method not in text:
    raise SystemExit("unexpected setup_host_image layout")
text = text.replace(setup_method, lazy_method, 1)
text = text.replace("self.docker_client.images", "(await self.get_docker_client()).images")
text = text.replace("self.docker_client.containers", "(await self.get_docker_client()).containers")
text = text.replace(".containers.get(container=container_name)", ".containers.get(container_id=container_name)")
text = text.replace(
    '        config = {"Cmd": cmd, "Image": image}\n',
    '        config = {"Cmd": cmd or ["sh", "-c", "true"], "Image": image}\n',
    1,
)
text = text.replace(
    "except (aiodocker.exceptions.DockerError or aiodocker.exceptions.DockerContainerError)",
    "except (aiodocker.exceptions.DockerError, aiodocker.exceptions.DockerContainerError)",
)

old = '''            if remote_path and tag is not None:
                params = {"tag": tag, "remote": remote_path}
                await (await self.get_docker_client()).images.build(**params)
'''
new = '''            if remote_path and tag is not None:
                # The isolated sandbox is pre-seeded and has no internet
                # egress. Reuse that image instead of rebuilding a remote
                # Dockerfile for every template-injection request.
                images = await (await self.get_docker_client()).images.list(filter=tag)
                if not images:
                    params = {"tag": tag, "remote": remote_path}
                    await (await self.get_docker_client()).images.build(**params)
'''
if old not in text:
    raise SystemExit("unexpected aiodocker_helper.py layout")
helper.write_text(text.replace(old, new))

# TANNER uses aioredis 2's connection factory, but two call sites still pass
# the per-command encoding argument removed by aioredis 2. Decode is already
# enabled for the client globally in redis_client.py.
for relative in ("sessions/session_analyzer.py", "dorks_manager.py"):
    target = Path("/opt/tanner/tanner") / relative
    source = target.read_text()
    source = source.replace(', encoding="utf-8"', "")
    target.write_text(source)
