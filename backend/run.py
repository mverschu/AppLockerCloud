"""
Run the FastAPI backend server.
"""
import uvicorn
import os

if __name__ == "__main__":
    # Allow port to be configured via environment variable
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=True
    )

