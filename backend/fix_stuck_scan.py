#!/usr/bin/env python3
"""Fix stuck scan by running it manually"""
import asyncio
from app.services.scanner import ScannerService
from app.utils.database import AsyncSessionLocal
from app.models.scan import Scan
from app.models.project import Project
from sqlalchemy import select
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def fix_stuck_scan():
    """Run the stuck scan manually"""
    async with AsyncSessionLocal() as db:
        try:
            # Get the stuck scan
            result = await db.execute(
                select(Scan, Project)
                .join(Project)
                .where(Scan.id == 11)
            )
            scan_project = result.first()
            if not scan_project:
                logger.error("Scan not found")
                return
            
            scan, project = scan_project
            logger.info(f"Found scan {scan.id} for project {project.name}")
            
            # Run the scanner
            scanner = ScannerService()
            logger.info("Starting scan...")
            await scanner.start_scan(scan.id, project, scan)
            logger.info("Scan completed successfully")
            
        except Exception as e:
            logger.error(f"Error running scan: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(fix_stuck_scan())