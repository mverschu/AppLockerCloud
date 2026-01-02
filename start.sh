#!/bin/bash
# Startup script for AppLocker Policy Creator (Client-side only)

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

# PID file for cleanup
FRONTEND_PID_FILE="$SCRIPT_DIR/.frontend.pid"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down services..."
    
    if [ -f "$FRONTEND_PID_FILE" ]; then
        FRONTEND_PID=$(cat "$FRONTEND_PID_FILE")
        if ps -p "$FRONTEND_PID" > /dev/null 2>&1; then
            kill "$FRONTEND_PID" 2>/dev/null
            echo "Frontend stopped (PID: $FRONTEND_PID)"
        fi
        rm -f "$FRONTEND_PID_FILE"
    fi
    
    echo "All services stopped."
    exit 0
}

# Trap Ctrl+C and cleanup
trap cleanup SIGINT SIGTERM

# Start frontend
echo "Starting frontend server..."
cd "$FRONTEND_DIR" || {
    echo "Error: Could not change to frontend directory: $FRONTEND_DIR"
    exit 1
}

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install || {
        echo "Error: Failed to install dependencies"
        exit 1
    }
fi

# Start frontend in background
npm run dev > "$SCRIPT_DIR/.frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "$FRONTEND_PID" > "$FRONTEND_PID_FILE"
echo "Frontend started (PID: $FRONTEND_PID) - http://localhost:3000"

echo ""
echo "=========================================="
echo "  AppLocker Policy Creator is running!"
echo "=========================================="
echo "  Frontend: http://localhost:3000"
echo ""
echo "  Logs:"
echo "    Frontend: $SCRIPT_DIR/.frontend.log"
echo ""
echo "  Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Wait for process
wait
