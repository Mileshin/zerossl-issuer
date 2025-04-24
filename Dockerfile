FROM python:3.12.5-alpine3.19

WORKDIR /app

# Install required packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python script
COPY src .

# Expose the port and run the application
EXPOSE 80
CMD ["python", "app.py"]