#!/bin/bash
# Unified startup script for AppLocker Policy Creator
# Starts both backend and frontend services

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

# PID files for cleanup
BACKEND_PID_FILE="$SCRIPT_DIR/.backend.pid"
FRONTEND_PID_FILE="$SCRIPT_DIR/.frontend.pid"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down services..."
    
    if [ -f "$BACKEND_PID_FILE" ]; then
        BACKEND_PID=$(cat "$BACKEND_PID_FILE")
        if ps -p "$BACKEND_PID" > /dev/null 2>&1; then
            kill "$BACKEND_PID" 2>/dev/null
            echo "Backend stopped (PID: $BACKEND_PID)"
        fi
        rm -f "$BACKEND_PID_FILE"
    fi
    
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

# Start backend
echo "Starting backend server..."
cd "$BACKEND_DIR" || {
    echo "Error: Could not change to backend directory: $BACKEND_DIR"
    exit 1
}

# Check if virtual environment exists
if [ ! -d "venv" ] || [ ! -f "venv/bin/activate" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv || {
        echo "Error: Failed to create virtual environment"
        exit 1
    }
fi

# Activate virtual environment
source venv/bin/activate || {
    echo "Error: Failed to activate virtual environment"
    exit 1
}

# Install dependencies if needed
if [ ! -f "venv/.installed" ] || [ "requirements.txt" -nt "venv/.installed" ] 2>/dev/null; then
    echo "Installing backend dependencies..."
    venv/bin/pip install --upgrade pip > /dev/null 2>&1
    venv/bin/pip install -r requirements.txt > /dev/null 2>&1 || {
        echo "Error: Failed to install dependencies"
        exit 1
    }
    touch venv/.installed
fi

# Start backend in background
venv/bin/python run.py > "$SCRIPT_DIR/.backend.log" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$BACKEND_PID_FILE"
echo "Backend started (PID: $BACKEND_PID) - http://localhost:8080"

# Start frontend
echo "Starting frontend server..."
cd "$FRONTEND_DIR" || {
    echo "Error: Could not change to frontend directory: $FRONTEND_DIR"
    cleanup
    exit 1
}

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install > /dev/null 2>&1 || {
        echo "Error: Failed to install dependencies"
        cleanup
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
echo "  Backend:  http://localhost:8080"
echo "  Frontend: http://localhost:3000"
echo ""
echo "  Logs:"
echo "    Backend:  $SCRIPT_DIR/.backend.log"
echo "    Frontend: $SCRIPT_DIR/.frontend.log"
echo ""
echo "  Press Ctrl+C to stop all services"
echo "=========================================="
echo ""

# Wait for both processes
wait

