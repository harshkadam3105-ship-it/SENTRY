from fastapi import WebSocket
from typing import List


class ConnectionManager:
    """Keeps track of connected dashboard clients and pushes live updates to all of them."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead_connections = []
        clients = list(self.active_connections)
        for connection in clients:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)
        print(f"[WebSocket] Broadcast '{message.get('type')}' to {len(clients) - len(dead_connections)} client(s)")


manager = ConnectionManager()
