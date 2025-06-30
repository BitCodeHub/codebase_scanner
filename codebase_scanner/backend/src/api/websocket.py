"""
WebSocket endpoints for real-time updates.
"""
import json
import asyncio
from typing import Dict, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from datetime import datetime
import redis.asyncio as redis

router = APIRouter()

# Connection manager for WebSocket clients
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.redis_client = None
    
    async def init_redis(self):
        """Initialize Redis connection for pub/sub."""
        if not self.redis_client:
            self.redis_client = await redis.from_url(
                "redis://localhost:6379",
                decode_responses=True
            )
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept WebSocket connection and add to active connections."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)
    
    def disconnect(self, websocket: WebSocket, scan_id: str):
        """Remove WebSocket from active connections."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific WebSocket."""
        await websocket.send_text(message)
    
    async def broadcast_to_scan(self, scan_id: str, message: dict):
        """Broadcast message to all connections watching a specific scan."""
        if scan_id in self.active_connections:
            disconnected = set()
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_text(json.dumps(message))
                except:
                    disconnected.add(connection)
            
            # Clean up disconnected clients
            for conn in disconnected:
                self.active_connections[scan_id].discard(conn)

# Global connection manager
manager = ConnectionManager()

@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan progress updates.
    
    Clients can connect to this endpoint to receive real-time updates
    about scan progress, including:
    - Status changes
    - Progress percentage
    - New vulnerabilities found
    - Scan completion
    """
    await manager.init_redis()
    await manager.connect(websocket, scan_id)
    
    try:
        # Send initial connection message
        await manager.send_personal_message(
            json.dumps({
                "type": "connection",
                "status": "connected",
                "scan_id": scan_id,
                "timestamp": datetime.utcnow().isoformat()
            }),
            websocket
        )
        
        # Subscribe to Redis channel for this scan
        pubsub = manager.redis_client.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}")
        
        # Listen for messages
        async def listen_redis():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    await manager.broadcast_to_scan(scan_id, json.loads(message["data"]))
        
        # Create task for Redis listener
        redis_task = asyncio.create_task(listen_redis())
        
        # Keep connection alive
        while True:
            try:
                # Wait for client messages (ping/pong)
                data = await websocket.receive_text()
                if data == "ping":
                    await manager.send_personal_message("pong", websocket)
            except WebSocketDisconnect:
                break
            except Exception as e:
                print(f"WebSocket error: {e}")
                break
        
    except WebSocketDisconnect:
        pass
    finally:
        # Clean up
        redis_task.cancel()
        await pubsub.unsubscribe(f"scan:{scan_id}")
        manager.disconnect(websocket, scan_id)

@router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """
    WebSocket endpoint for dashboard real-time updates.
    
    Provides real-time updates for:
    - New scans started
    - Scan completions
    - Critical vulnerabilities found
    - System alerts
    """
    await manager.init_redis()
    await websocket.accept()
    
    try:
        # Subscribe to dashboard channel
        pubsub = manager.redis_client.pubsub()
        await pubsub.subscribe("dashboard:updates")
        
        # Send initial connection message
        await websocket.send_text(json.dumps({
            "type": "connection",
            "status": "connected",
            "timestamp": datetime.utcnow().isoformat()
        }))
        
        # Listen for messages
        async def listen_redis():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    await websocket.send_text(message["data"])
        
        # Create task for Redis listener
        redis_task = asyncio.create_task(listen_redis())
        
        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
            except WebSocketDisconnect:
                break
            except Exception as e:
                print(f"WebSocket error: {e}")
                break
        
    except WebSocketDisconnect:
        pass
    finally:
        redis_task.cancel()
        await pubsub.unsubscribe("dashboard:updates")

# Helper functions to send updates
async def send_scan_progress(scan_id: str, progress: dict):
    """Send scan progress update via Redis pub/sub."""
    if manager.redis_client:
        await manager.redis_client.publish(
            f"scan:{scan_id}",
            json.dumps({
                "type": "progress",
                "scan_id": scan_id,
                "progress": progress,
                "timestamp": datetime.utcnow().isoformat()
            })
        )

async def send_scan_result(scan_id: str, result: dict):
    """Send new scan result via Redis pub/sub."""
    if manager.redis_client:
        await manager.redis_client.publish(
            f"scan:{scan_id}",
            json.dumps({
                "type": "result",
                "scan_id": scan_id,
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            })
        )

async def send_dashboard_update(update_type: str, data: dict):
    """Send dashboard update via Redis pub/sub."""
    if manager.redis_client:
        await manager.redis_client.publish(
            "dashboard:updates",
            json.dumps({
                "type": update_type,
                "data": data,
                "timestamp": datetime.utcnow().isoformat()
            })
        )