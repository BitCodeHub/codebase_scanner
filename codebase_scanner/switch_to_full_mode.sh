#!/bin/bash
# Script to switch from simple mode to full mode after environment variables are configured

echo "Switching to full application mode..."

# Update render.yaml to use full applications
sed -i.bak 's/app\.main_simple:app/app.main:app/g' ../render.yaml
sed -i.bak 's/app\.celery_app_simple/app.celery_app/g' ../render.yaml

echo "Changes made:"
echo "- Backend will use app.main:app"
echo "- Worker will use app.celery_app"
echo ""
echo "Please commit and push these changes to deploy with full functionality:"
echo "  git add render.yaml"
echo "  git commit -m 'chore: switch to full application mode'"
echo "  git push origin main"