from moviepy.editor import *
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import os

def create_text_clip(text, size=(1080, 200), duration=5, fontsize=60):
    # Create a white background
    img = Image.new('RGB', size, 'white')
    draw = ImageDraw.Draw(img)
    
    # Load a font (you'll need to specify a font file path or use default)
    try:
        font = ImageFont.truetype("Arial.ttf", fontsize)
    except:
        font = ImageFont.load_default()
    
    # Calculate text position to center it
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    x = (size[0] - text_width) // 2
    y = (size[1] - text_height) // 2
    
    # Draw the text
    draw.text((x, y), text, font=font, fill='black')
    
    # Convert to MoviePy clip
    return ImageClip(np.array(img)).set_duration(duration)

def create_image_grid(image_paths, labels, size=(1080, 800), duration=5):
    # Create a white background
    background = Image.new('RGB', size, 'white')
    
    # Calculate dimensions for each image
    img_width = size[0] // 2
    img_height = (size[1] // 2) - 30  # Leave space for labels
    
    # Positions for the four images
    positions = [
        (0, 0),                    # Top left
        (img_width, 0),            # Top right
        (0, img_height + 60),      # Bottom left
        (img_width, img_height + 60)  # Bottom right
    ]
    
    # Load and paste each image
    for i, (img_path, label, pos) in enumerate(zip(image_paths, labels, positions)):
        # Load and resize image
        try:
            img = Image.open(img_path)
            img = img.resize((img_width, img_height), Image.Resampling.LANCZOS)
            background.paste(img, pos)
            
            # Add label
            draw = ImageDraw.Draw(background)
            try:
                font = ImageFont.truetype("Arial.ttf", 30)
            except:
                font = ImageFont.load_default()
            
            # Draw label centered under the image
            label_bbox = draw.textbbox((0, 0), label, font=font)
            label_width = label_bbox[2] - label_bbox[0]
            x = pos[0] + (img_width - label_width) // 2
            y = pos[1] + img_height + 10
            draw.text((x, y), label, font=font, fill='black')
            
        except Exception as e:
            print(f"Error processing image {img_path}: {e}")
    
    return ImageClip(np.array(background)).set_duration(duration)

def create_video(title, image_paths, labels, output_path="output.mp4"):
    # Create the title clip
    title_clip = create_text_clip(title)
    
    # Create the image grid clip
    grid_clip = create_image_grid(image_paths, labels)
    
    # Combine clips vertically
    final_clip = clips_array([[title_clip], [grid_clip]])
    
    # Write the video file
    final_clip.write_videofile(output_path, fps=24)

# Example usage
if __name__ == "__main__":
    title = "People who are the most productive at their job"
    
    # Replace these with actual image paths
    image_paths = [
        "office_worker.jpg",
        "construction_worker.jpg",
        "doctor.jpg",
        "teacher.jpg"
    ]
    
    labels = [
        "Office Worker",
        "Construction",
        "Doctor",
        "Teacher"
    ]
    
    create_video(title, image_paths, labels)
