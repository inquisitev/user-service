# Use a Python base image`
FROM python:3.9-slim-buster

# Set the working directory
WORKDIR /app

# Copy the authentication API source code to the container
COPY src/authService.py /app/authService.py

# Copy the requirements file to the container
COPY requirements.txt /app/requirements.txt

# Install the necessary packages
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 3004 for the authentication API
EXPOSE 3004

# Start the authentication API using Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:3004", "authService:app"]
