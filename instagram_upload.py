import os
from instagrapi import Client
from instagrapi.exceptions import (
    LoginRequired,
    ClientError,
    ClientLoginRequired,
    ClientCookieExpiredError,
    ClientThrottledError
)
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class InstagramUploader:
    def __init__(self):
        self.client = Client()
        self.session_file = Path("instagram_session.json")
        
    def login(self, username, password):
        """Login to Instagram account"""
        try:
            if self.session_file.exists():
                self.client.load_settings(self.session_file)
                self.client.login(username, password)
            else:
                self.client.login(username, password)
                self.client.dump_settings(self.session_file)
            logger.info("Successfully logged in to Instagram")
            return True
        except (ClientLoginRequired, ClientCookieExpiredError) as e:
            logger.error(f"Login failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during login: {e}")
            return False

    def upload_video(self, video_path, caption=""):
        """Upload video to Instagram"""
        try:
            if not os.path.exists(video_path):
                logger.error(f"Video file not found: {video_path}")
                return False

            # Upload the video
            media = self.client.clip_upload(
                path=video_path,
                caption=caption
            )
            logger.info(f"Successfully uploaded video. Media ID: {media.id}")
            return True
        except (LoginRequired, ClientError) as e:
            logger.error(f"Upload failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during upload: {e}")
            return False

def main():
    # Create uploader instance
    uploader = InstagramUploader()
    
    # Get credentials from environment variables or user input
    username = os.getenv("INSTAGRAM_USERNAME")
    password = os.getenv("INSTAGRAM_PASSWORD")
    
    if not username or not password:
        username = input("Enter Instagram username: ")
        password = input("Enter Instagram password: ")
    
    # Login to Instagram
    if not uploader.login(username, password):
        logger.error("Failed to login to Instagram")
        return
    
    # Upload video
    video_path = "output.mp4"
    caption = "Uploaded via Python script"  # You can customize this
    
    if uploader.upload_video(video_path, caption):
        logger.info("Video upload completed successfully")
    else:
        logger.error("Video upload failed")

if __name__ == "__main__":
    main()
