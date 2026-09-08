import docker

client = docker.from_env()


def isolate_host(container_name: str) -> dict:
    """
    Disconnects a container from all its Docker networks — this is the
    demo's 'we don't just detect, we respond' action.
    container_name must match the container name of the 'attacked' host
    in your Docker Compose setup.
    """
    try:
        container = client.containers.get(container_name)
        networks = container.attrs["NetworkSettings"]["Networks"]

        disconnected_from = []
        for network_name in networks:
            network = client.networks.get(network_name)
            network.disconnect(container)
            disconnected_from.append(network_name)

        return {
            "status": "isolated",
            "container": container_name,
            "disconnected_from": disconnected_from,
        }
    except docker.errors.NotFound:
        return {"status": "error", "detail": f"Container '{container_name}' not found"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def restore_host(container_name: str, network_name: str) -> dict:
    """Reconnects a container back to a network — lets you re-run the demo without restarting containers."""
    try:
        container = client.containers.get(container_name)
        network = client.networks.get(network_name)
        network.connect(container)
        return {"status": "restored", "container": container_name, "network": network_name}
    except docker.errors.NotFound as e:
        return {"status": "error", "detail": str(e)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
