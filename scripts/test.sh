#!/bin/bash

# CredStor Test Runner Script
# This script runs the test suite with various options

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to display help
show_help() {
    echo "CredStor Test Runner"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -u, --unit       Run only unit tests"
    echo "  -i, --integration Run only integration tests"
    echo "  -s, --security   Run only security tests"
    echo "  -c, --coverage   Run tests with coverage report"
    echo "  -v, --verbose    Verbose output"
    echo "  -f, --fast       Skip slow tests"
    echo "  --watch          Watch for file changes and re-run tests"
    echo "  --html           Generate HTML coverage report"
    echo "  --clean          Clean test artifacts before running"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all tests"
    echo "  $0 -u -c             # Run unit tests with coverage"
    echo "  $0 -s -v             # Run security tests with verbose output"
    echo "  $0 --clean --html    # Clean artifacts and generate HTML report"
}

# Default options
RUN_UNIT=false
RUN_INTEGRATION=false
RUN_SECURITY=false
COVERAGE=false
VERBOSE=false
FAST=false
WATCH=false
HTML=false
CLEAN=false
RUN_ALL=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -u|--unit)
            RUN_UNIT=true
            RUN_ALL=false
            shift
            ;;
        -i|--integration)
            RUN_INTEGRATION=true
            RUN_ALL=false
            shift
            ;;
        -s|--security)
            RUN_SECURITY=true
            RUN_ALL=false
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--fast)
            FAST=true
            shift
            ;;
        --watch)
            WATCH=true
            shift
            ;;
        --html)
            HTML=true
            COVERAGE=true  # HTML implies coverage
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Check if virtual environment is activated
if [[ -z "$VIRTUAL_ENV" ]]; then
    print_warning "Virtual environment not detected. Activating..."
    if [[ -f "venv/bin/activate" ]]; then
        source venv/bin/activate
        print_status "Virtual environment activated"
    else
        print_error "Virtual environment not found. Run setup.sh first."
        exit 1
    fi
fi

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    print_error "pytest not found. Installing test dependencies..."
    pip install pytest pytest-cov pytest-asyncio pytest-xdist
fi

# Clean test artifacts if requested
if [[ "$CLEAN" == true ]]; then
    print_step "Cleaning test artifacts..."
    rm -rf .pytest_cache
    rm -rf htmlcov
    rm -f .coverage
    rm -f coverage.xml
    find . -type d -name "__pycache__" -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete
    print_status "Test artifacts cleaned"
fi

# Build pytest command
PYTEST_CMD="pytest"

# Add test markers based on options
if [[ "$RUN_ALL" == true ]]; then
    PYTEST_CMD="$PYTEST_CMD tests/"
else
    TEST_MARKERS=""
    
    if [[ "$RUN_UNIT" == true ]]; then
        TEST_MARKERS="$TEST_MARKERS unit"
    fi
    
    if [[ "$RUN_INTEGRATION" == true ]]; then
        TEST_MARKERS="$TEST_MARKERS integration"
    fi
    
    if [[ "$RUN_SECURITY" == true ]]; then
        TEST_MARKERS="$TEST_MARKERS security"
    fi
    
    if [[ -n "$TEST_MARKERS" ]]; then
        # Convert space-separated markers to "or" expression
        MARKER_EXPR=$(echo "$TEST_MARKERS" | sed 's/ / or /g')
        PYTEST_CMD="$PYTEST_CMD -m \"$MARKER_EXPR\""
    fi
    
    PYTEST_CMD="$PYTEST_CMD tests/"
fi

# Add coverage options
if [[ "$COVERAGE" == true ]]; then
    PYTEST_CMD="$PYTEST_CMD --cov=src --cov-report=term-missing"
    
    if [[ "$HTML" == true ]]; then
        PYTEST_CMD="$PYTEST_CMD --cov-report=html:htmlcov"
    fi
    
    PYTEST_CMD="$PYTEST_CMD --cov-report=xml"
fi

# Add verbose option
if [[ "$VERBOSE" == true ]]; then
    PYTEST_CMD="$PYTEST_CMD -v"
fi

# Add fast option (skip slow tests)
if [[ "$FAST" == true ]]; then
    PYTEST_CMD="$PYTEST_CMD -m \"not slow\""
fi

# Watch mode
if [[ "$WATCH" == true ]]; then
    print_step "Running tests in watch mode..."
    print_status "Watching for file changes. Press Ctrl+C to stop."
    
    # Install pytest-watch if not available
    if ! command -v ptw &> /dev/null; then
        pip install pytest-watch
    fi
    
    # Use pytest-watch
    eval "ptw -- $PYTEST_CMD"
else
    # Regular test run
    print_step "Running CredStor test suite..."
    echo "Command: $PYTEST_CMD"
    echo ""
    
    # Set PYTHONPATH to include src
    export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
    
    # Run tests
    eval "$PYTEST_CMD"
    
    # Check exit code
    TEST_EXIT_CODE=$?
    
    if [[ $TEST_EXIT_CODE -eq 0 ]]; then
        print_status "All tests passed!"
        
        if [[ "$HTML" == true ]]; then
            print_status "HTML coverage report generated in htmlcov/"
            if command -v open &> /dev/null; then
                print_status "Opening coverage report..."
                open htmlcov/index.html
            fi
        fi
    else
        print_error "Some tests failed!"
        exit $TEST_EXIT_CODE
    fi
fi

# Display coverage summary if available
if [[ "$COVERAGE" == true && -f ".coverage" ]]; then
    echo ""
    print_step "Coverage Summary:"
    coverage report --skip-covered
fi

print_status "Test run completed!"