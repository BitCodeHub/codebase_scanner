#!/usr/bin/env python3
"""Create demo user for testing"""
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from app.utils.database import AsyncSessionLocal
from app.models.user import User
from app.utils.security import get_password_hash
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def create_demo_user():
    """Create demo user if it doesn't exist"""
    async with AsyncSessionLocal() as db:
        try:
            # Check if demo user exists
            from sqlalchemy import select
            result = await db.execute(select(User).where(User.username == "demo"))
            existing_user = result.scalar_one_or_none()
            
            if existing_user:
                logger.info("Demo user already exists")
                return
            
            # Create demo user
            demo_user = User(
                username="demo",
                email="demo@example.com",
                hashed_password=get_password_hash("demo123"),
                full_name="Demo User",
                is_active=True
            )
            
            db.add(demo_user)
            await db.commit()
            logger.info("Demo user created successfully")
            logger.info("Username: demo")
            logger.info("Password: demo123")
            
        except Exception as e:
            logger.error(f"Error creating demo user: {e}")
            await db.rollback()


if __name__ == "__main__":
    asyncio.run(create_demo_user())