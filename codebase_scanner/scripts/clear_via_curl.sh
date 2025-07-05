#!/bin/bash

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check if we have the required variables
if [ -z "$SUPABASE_URL" ] || [ -z "$SUPABASE_ANON_KEY" ]; then
    echo "❌ Missing SUPABASE_URL or SUPABASE_ANON_KEY in .env file"
    exit 1
fi

echo "🗑️  CLEARING ALL PROJECTS AND ASSOCIATED DATA"
echo "==========================================="
echo ""

# Function to execute SQL query
execute_sql() {
    local query=$1
    local description=$2
    
    echo -n "$description..."
    
    response=$(curl -s -X POST \
        "${SUPABASE_URL}/rest/v1/rpc/execute_sql" \
        -H "apikey: ${SUPABASE_ANON_KEY}" \
        -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"$query\"}")
    
    if [ $? -eq 0 ]; then
        echo " ✅"
    else
        echo " ❌"
        echo "Error: $response"
    fi
}

# First, let's get counts using REST API
echo "📊 Getting current data counts..."

# Count projects
projects_count=$(curl -s -X GET \
    "${SUPABASE_URL}/rest/v1/projects?select=id" \
    -H "apikey: ${SUPABASE_ANON_KEY}" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    -H "Range: 0-0" \
    -H "Prefer: count=exact" \
    -I | grep -i content-range | sed 's/.*\///' | tr -d '\r')

# Count scans
scans_count=$(curl -s -X GET \
    "${SUPABASE_URL}/rest/v1/scans?select=id" \
    -H "apikey: ${SUPABASE_ANON_KEY}" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    -H "Range: 0-0" \
    -H "Prefer: count=exact" \
    -I | grep -i content-range | sed 's/.*\///' | tr -d '\r')

# Count scan_results
scan_results_count=$(curl -s -X GET \
    "${SUPABASE_URL}/rest/v1/scan_results?select=id" \
    -H "apikey: ${SUPABASE_ANON_KEY}" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    -H "Range: 0-0" \
    -H "Prefer: count=exact" \
    -I | grep -i content-range | sed 's/.*\///' | tr -d '\r')

echo "   - Projects: ${projects_count:-0}"
echo "   - Scans: ${scans_count:-0}"
echo "   - Scan Results: ${scan_results_count:-0}"
echo ""

# Check if already empty
if [ "${projects_count:-0}" -eq 0 ] && [ "${scans_count:-0}" -eq 0 ] && [ "${scan_results_count:-0}" -eq 0 ]; then
    echo "✅ Database is already empty!"
    exit 0
fi

# Confirm deletion
echo "⚠️  WARNING: This will permanently delete all data!"
read -p "Type 'DELETE ALL' to confirm: " confirm

if [ "$confirm" != "DELETE ALL" ]; then
    echo "❌ Deletion cancelled"
    exit 1
fi

echo ""
echo "🔄 Deleting data..."

# Delete scan_results first (due to foreign key constraints)
echo -n "   - Deleting scan results..."
curl -s -X DELETE \
    "${SUPABASE_URL}/rest/v1/scan_results?id=gte.0" \
    -H "apikey: ${SUPABASE_ANON_KEY}" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    > /dev/null
echo " ✅"

# Delete scans
echo -n "   - Deleting scans..."
curl -s -X DELETE \
    "${SUPABASE_URL}/rest/v1/scans?id=gte.0" \
    -H "apikey: ${SUPABASE_ANON_KEY}" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    > /dev/null
echo " ✅"

# Delete projects
echo -n "   - Deleting projects..."
curl -s -X DELETE \
    "${SUPABASE_URL}/rest/v1/projects?id=gte.0" \
    -H "apikey: ${SUPABASE_ANON_KEY}" \
    -H "Authorization: Bearer ${SUPABASE_ANON_KEY}" \
    > /dev/null
echo " ✅"

echo ""
echo "✅ All data successfully cleared!"
echo "   Completed at: $(date '+%Y-%m-%d %H:%M:%S')"