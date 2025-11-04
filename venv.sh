#!/bin/bash
#
# venv.sh - Prepare Python virtual environment for avxdump
#
# This script creates and sets up a Python virtual environment with all
# required dependencies for the avxdump AVX session analysis tool.
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error${NC}: python3 not found. Please install Python 3.7 or later."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    echo -e "${RED}Error${NC}: Python 3.7 or later is required. Found: $PYTHON_VERSION"
    exit 1
fi

echo "Python version: $PYTHON_VERSION"
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists at: $VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip --quiet
# Core dependencies
pip install capstone==5.0.6 
pip install pyelftools==0.32 

echo ""
echo "To activate the virtual environment, run:"
echo "    source venv/bin/activate"
echo "Or use the virtual environment directly:"
echo "    source venv/bin/activate && python3 avxdump.py <binary>"
