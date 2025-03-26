"""
Main application entry point
"""

import sys
import logging
from PyQt6.QtWidgets import QApplication
from ui import MainWindow

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def reset():
    with open('ioc.csv', 'w') as file:
        pass

def check_dependencies():
    """Check if all required dependencies are available"""
    try:
        import PyQt6
        import requests
        import dotenv
        logger.info("All required dependencies are available")
        return True
    except ImportError as e:
        logger.error(f"Missing dependency: {str(e)}")
        return False

def main():
    """Main application entry point"""
    try:
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)

        # Create application
        app = QApplication(sys.argv)
        
        # Create and show main window
        window = MainWindow()
        window.show()

        # Start event loop
        sys.exit(app.exec())
        
        
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    reset()
    main()
