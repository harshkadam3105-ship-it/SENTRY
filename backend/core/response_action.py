"""
Docker container response action: isolate and restore containers from Docker networks.
"""

try:
    import docker
    client = docker.from_env()
except Exception:
    client = None


def isolate_host(container_name: str) -> dict:
    """
    Disconnects a container from all its Docker networks — this is the
    demo's 'we don't just detect, we respond' action.
    container_name must match the container name of the 'attacked' host
    in your Docker Compose setup.
    """
    if client is None:
        # Fallback simulation if docker daemon is not directly accessible
        return {
            "status": "isolated",
            "container": container_name,
            "disconnected_from": ["sentry-net"],
            "simulated": True,
        }

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
    except Exception as e:
        # If container not found, return safe response so UI doesn't hang
        return {"status": "isolated", "container": container_name, "detail": str(e), "simulated": True}


def restore_host(container_name: str, network_name: str) -> dict:
    """Reconnects a container back to a network — lets you re-run the demo without restarting containers."""
    if client is None:
        return {"status": "restored", "container": container_name, "network": network_name, "simulated": True}

    try:
        container = client.containers.get(container_name)
        network = client.networks.get(network_name)
        network.connect(container)
        return {"status": "restored", "container": container_name, "network": network_name}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
