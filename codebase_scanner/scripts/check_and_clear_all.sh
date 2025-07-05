#!/bin/bash

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Use SERVICE role key for full access
AUTH_KEY="${SUPABASE_SERVICE_KEY:-$SUPABASE_ANON_KEY}"

if [ -z "$SUPABASE_URL" ] || [ -z "$AUTH_KEY" ]; then
    echo "❌ Missing SUPABASE_URL or SUPABASE_SERVICE_KEY in .env file"
    exit 1
fi

echo "🔍 CHECKING ALL DATA IN SUPABASE"
echo "=================================="
echo "URL: $SUPABASE_URL"
echo "Using service role key: ${AUTH_KEY:0:20}..."
echo ""

# Function to get all records from a table
get_all_records() {
    local table=$1
    local response=$(curl -s -X GET \
        "${SUPABASE_URL}/rest/v1/${table}?select=*" \
        -H "apikey: ${AUTH_KEY}" \
        -H "Authorization: Bearer ${AUTH_KEY}" \
        -H "Prefer: count=exact")
    
    echo "$response"
}

# Check projects
echo "📊 Projects:"
projects=$(get_all_records "projects")
project_count=$(echo "$projects" | jq '. | length' 2>/dev/null || echo "0")
echo "   Count: $project_count"
if [ "$project_count" -gt 0 ]; then
    echo "$projects" | jq -r '.[] | "   - ID: \(.id), Name: \(.name), Owner: \(.owner_id)"' 2>/dev/null || echo "   Error parsing projects"
fi
echo ""

# Check scans
echo "📊 Scans:"
scans=$(get_all_records "scans")
scan_count=$(echo "$scans" | jq '. | length' 2>/dev/null || echo "0")
echo "   Count: $scan_count"
echo ""

# Check scan_results
echo "📊 Scan Results:"
scan_results=$(get_all_records "scan_results")
scan_results_count=$(echo "$scan_results" | jq '. | length' 2>/dev/null || echo "0")
echo "   Count: $scan_results_count"
echo ""

# If there's data, offer to delete it
if [ "$project_count" -gt 0 ] || [ "$scan_count" -gt 0 ] || [ "$scan_results_count" -gt 0 ]; then
    echo "⚠️  Found existing data in the database!"
    read -p "Do you want to DELETE ALL data? Type 'DELETE ALL' to confirm: " confirm
    
    if [ "$confirm" = "DELETE ALL" ]; then
        echo ""
        echo "🗑️  Deleting all data..."
        
        # Delete with service role key (has full permissions)
        # Delete scan_results first
        echo -n "   - Deleting scan results..."
        curl -s -X DELETE \
            "${SUPABASE_URL}/rest/v1/scan_results?id=gte.0" \
            -H "apikey: ${AUTH_KEY}" \
            -H "Authorization: Bearer ${AUTH_KEY}" \
            -H "Prefer: return=minimal" \
            > /dev/null
        echo " ✅"
        
        # Delete scans
        echo -n "   - Deleting scans..."
        curl -s -X DELETE \
            "${SUPABASE_URL}/rest/v1/scans?id=gte.0" \
            -H "apikey: ${AUTH_KEY}" \
            -H "Authorization: Bearer ${AUTH_KEY}" \
            -H "Prefer: return=minimal" \
            > /dev/null
        echo " ✅"
        
        # Delete projects
        echo -n "   - Deleting projects..."
        curl -s -X DELETE \
            "${SUPABASE_URL}/rest/v1/projects?id=gte.0" \
            -H "apikey: ${AUTH_KEY}" \
            -H "Authorization: Bearer ${AUTH_KEY}" \
            -H "Prefer: return=minimal" \
            > /dev/null
        echo " ✅"
        
        echo ""
        echo "✅ All data deleted!"
        echo ""
        echo "📊 Verifying deletion..."
        
        # Re-check counts
        projects_after=$(curl -s -X GET \
            "${SUPABASE_URL}/rest/v1/projects?select=*" \
            -H "apikey: ${AUTH_KEY}" \
            -H "Authorization: Bearer ${AUTH_KEY}" | jq '. | length' 2>/dev/null || echo "0")
        
        scans_after=$(curl -s -X GET \
            "${SUPABASE_URL}/rest/v1/scans?select=*" \
            -H "apikey: ${AUTH_KEY}" \
            -H "Authorization: Bearer ${AUTH_KEY}" | jq '. | length' 2>/dev/null || echo "0")
        
        scan_results_after=$(curl -s -X GET \
            "${SUPABASE_URL}/rest/v1/scan_results?select=*" \
            -H "apikey: ${AUTH_KEY}" \
            -H "Authorization: Bearer ${AUTH_KEY}" | jq '. | length' 2>/dev/null || echo "0")
        
        echo "   - Projects remaining: $projects_after"
        echo "   - Scans remaining: $scans_after"
        echo "   - Scan Results remaining: $scan_results_after"
        
        if [ "$projects_after" = "0" ] && [ "$scans_after" = "0" ] && [ "$scan_results_after" = "0" ]; then
            echo ""
            echo "✅ Database is now completely empty!"
            echo ""
            echo "💡 Next steps:"
            echo "   1. Refresh your browser (Cmd+R or Ctrl+R)"
            echo "   2. If projects still show, clear browser cache:"
            echo "      - Chrome/Edge: Cmd+Shift+R (Mac) or Ctrl+Shift+R (Windows)"
            echo "      - Or open Developer Tools > Application > Clear Storage"
        else
            echo ""
            echo "⚠️  Some data may still remain. Try running this script again."
        fi
    else
        echo "❌ Deletion cancelled"
    fi
else
    echo "✅ Database is already empty!"
fi