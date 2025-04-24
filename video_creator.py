from moviepy.editor import *
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import os
import requests
import tempfile
from urllib.parse import quote

# Add music file paths
MUSIC_CHOICES = {
    '1': 'background_music/chill.mp3',
    '2': 'background_music/suspense.mp3',
    '3': 'background_music/upbeat.mp3'
}

def download_image(url, label):
    """Download image from URL and save it temporarily"""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Create a temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.jpg')
        
        # Save the image
        for chunk in response.iter_content(chunk_size=8192):
            temp_file.write(chunk)
        
        temp_file.close()
        return temp_file.name
    except Exception as e:
        print(f"Error downloading image for {label}: {e}")
        return None

def get_unsplash_image(query):
    """Fetch a random image from Unsplash based on the query"""
    try:
        # Replace this with your Unsplash API access key
        access_key = 'w3puTZ-pDkfeZ_rE67yEEE-q5xPBsz_wtqxIJyEMROo'
        
        # Search for images with landscape orientation
        url = f'https://api.unsplash.com/photos/random?query={quote(query)}&orientation=landscape'
        headers = {
            'Authorization': f'Client-ID {access_key}',
            'Accept-Version': 'v1'
        }
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        return data['urls']['regular']  # Get the regular size image URL
    except Exception as e:
        print(f"Error fetching image for {query}: {e}")
        return None

def create_text_clip(text, size=(1080, 700), duration=5, fontsize=90):
    # Create a white background
    img = Image.new('RGB', size, 'white')
    draw = ImageDraw.Draw(img)
    
    # Load a font (you'll need to specify a font file path or use default)
    try:
        # Try to load a bold font, fall back to Arial if not available
        try:
            font = ImageFont.truetype("Arial Bold.ttf", fontsize)
        except:
            font = ImageFont.truetype("Arial.ttf", fontsize)
    except:
        font = ImageFont.load_default()
    
    # Calculate maximum width for text (leaving some padding)
    max_width = size[0] - 100  # 50px padding on each side
    
    # Split text into words
    words = text.split()
    lines = []
    current_line = []
    
    # Create wrapped lines
    for word in words:
        # Test if adding this word would exceed max width
        test_line = ' '.join(current_line + [word])
        test_bbox = draw.textbbox((0, 0), test_line, font=font)
        test_width = test_bbox[2] - test_bbox[0]
        
        if test_width <= max_width:
            current_line.append(word)
        else:
            if current_line:
                lines.append(' '.join(current_line))
            current_line = [word]
    
    # Add the last line if it exists
    if current_line:
        lines.append(' '.join(current_line))
    
    # Calculate total height needed
    total_height = len(lines) * (fontsize + 10)  # 10px spacing between lines
    
    # If text is too tall, reduce font size
    while total_height > size[1] - 20 and fontsize > 20:  # 20px padding top and bottom
        fontsize -= 5
        try:
            try:
                font = ImageFont.truetype("Arial Bold.ttf", fontsize)
            except:
                font = ImageFont.truetype("Arial.ttf", fontsize)
        except:
            font = ImageFont.load_default()
        total_height = len(lines) * (fontsize + 10)
    
    # Draw each line
    y = (size[1] - total_height) // 2 + 250  # Center vertically and move down 50px (reduced from 100px)
    for line in lines:
        # Calculate text position to center it horizontally
        text_bbox = draw.textbbox((0, 0), line, font=font)
        text_width = text_bbox[2] - text_bbox[0]
        x = (size[0] - text_width) // 2
        
        # Draw the text
        draw.text((x, y), line, font=font, fill='black')
        y += fontsize + 10  # Move to next line
    
    # Convert to MoviePy clip
    return ImageClip(np.array(img)).set_duration(duration)

def create_image_grid(image_paths, labels, size=(1080, 1620), duration=5):
    # Create a white background
    background = Image.new('RGB', size, 'white')
    draw = ImageDraw.Draw(background)
    
    # Calculate dimensions for each image with adjusted spacing
    # Start much higher in the frame
    available_height = size[1] - 300  # Reduced from 400 to start higher
    available_width = size[0] - 150   # 50px left + 50px right + 50px between images
    
    # Set 4:3 aspect ratio dimensions for more vertical-friendly images
    # Each image will be 1/2 of the available width and maintain 4:3 ratio
    img_width = available_width // 2
    img_height = int(img_width * 3 / 4)  # Calculate height based on 4:3 ratio
    
    # Calculate vertical spacing between rows
    vertical_spacing = (available_height - (2 * img_height)) // 3
    
    # Positions for the four images with adjusted spacing
    positions = [
        (50, 25 + vertical_spacing),                    # Top left (moved up from 50)
        (img_width + 100, 25 + vertical_spacing),       # Top right (moved up from 50)
        (50, 25 + img_height + 2 * vertical_spacing),  # Bottom left (moved up from 50)
        (img_width + 100, 25 + img_height + 2 * vertical_spacing)  # Bottom right (moved up from 50)
    ]
    
    # Load and paste each image
    for i, (img_path, label, pos) in enumerate(zip(image_paths, labels, positions)):
        # Add label first (above the image)
        try:
            try:
                # Try to load a bold font, fall back to Arial if not available
                try:
                    font = ImageFont.truetype("Arial Bold.ttf", 50)  # Increased font size
                except:
                    font = ImageFont.truetype("Arial.ttf", 50)  # Increased font size
            except:
                font = ImageFont.load_default()
            
            # Draw label centered above the image
            label_bbox = draw.textbbox((0, 0), label, font=font)
            label_width = label_bbox[2] - label_bbox[0]
            x = pos[0] + (img_width - label_width) // 2
            y = pos[1] - 60  # Position label 50px above the image
            draw.text((x, y), label, font=font, fill='black')
            
            # Load and resize image
            img = Image.open(img_path)
            # Force resize to exact dimensions with 4:3 ratio
            img = img.resize((img_width, img_height), Image.Resampling.LANCZOS)
            
            # Calculate position to center the image in its grid cell
            paste_x = pos[0] + (img_width - img.width) // 2
            paste_y = pos[1]  # No need to center vertically since we have the label above
            
            background.paste(img, (paste_x, paste_y))
            
        except Exception as e:
            print(f"Error processing image {img_path}: {e}")
    
    return ImageClip(np.array(background)).set_duration(duration)

def create_video(title, labels, output_path="output.mp4"):
    # Fetch images for each label
    image_paths = []
    temp_files = []
    
    for label in labels:
        image_url = get_unsplash_image(label)
        if image_url:
            temp_path = download_image(image_url, label)
            if temp_path:
                image_paths.append(temp_path)
                temp_files.append(temp_path)
    
    if not image_paths:
        raise Exception("Failed to fetch any images")
    
    # Create the title clip
    title_clip = create_text_clip(title)
    
    # Create the image grid clip
    grid_clip = create_image_grid(image_paths, labels)
    
    # Combine clips vertically
    final_clip = clips_array([[title_clip], [grid_clip]])
    
    # Add fade-in effect (0.5 second duration)
    final_clip = final_clip.fadein(0.5)
    
    # Get music choice from user
    while True:
        print("\nSelect background music:")
        print("1. Chill")
        print("2. Suspense")
        print("3. Upbeat")
        choice = input("Enter your choice (1-3): ")
        
        if choice in MUSIC_CHOICES:
            music_path = MUSIC_CHOICES[choice]
            if os.path.exists(music_path):
                break
            else:
                print(f"Error: Music file {music_path} not found. Please ensure the music files are in the same directory.")
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
    
    # Add background music
    audio = AudioFileClip(music_path)
    
    # Set audio volume to 30% of original
    audio = audio.volumex(0.2)
    
    # Trim audio to match video duration
    audio = audio.subclip(0, final_clip.duration)
    
    # Set the audio of the video
    final_clip = final_clip.set_audio(audio)
    
    # Write the video file
    final_clip.write_videofile(output_path, fps=24)
    
    # Clean up temporary files
    for temp_file in temp_files:
        try:
            os.unlink(temp_file)
        except:
            pass

# Example usage
if __name__ == "__main__":
    title = "Most productive tools"
    
    labels = [
        "Computer",
        "Phone",
        "Tablet",
        "Smartwatch",
    ]
    
    create_video(title, labels)
