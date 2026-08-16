cd /opt/nexusai-inference
git pull origin main
npm ci --omit=dev
npm run build
cat .env
cp .env.example .env
docker compose pull
docker compose up -d
docker compose logs -f --tail=50 portal
pm2 status
pm2 restart portal
pm2 logs portal --lines 100
psql "$DATABASE_URL" -c '\dt'
redis-cli -h cache-01 -a "$REDIS_PASSWORD" ping
node scripts/migrate.js --dry-run
scp db-01:/var/backups/portal/latest.sql.gz ./tmp/
gzip -d tmp/latest.sql.gz
ls -la ~/.ssh
ssh deploy@web-02 'systemctl --user status portal'
curl -sS -H "Authorization: Bearer $PORTAL_API_KEY" http://127.0.0.1:3000/api/v1/status
history
exit
